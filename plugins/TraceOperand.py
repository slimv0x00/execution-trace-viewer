from z3 import *
from enum import Enum, auto
from capstone import x86, CS_AC_WRITE, CS_AC_READ


# 오퍼랜드 타입 정의
class OperandType(Enum):
    REG = auto()  # 레지스터 (rax, ebx...)
    MEM = auto()  # 메모리 ([rax+rcx*8+4]...)
    IMM = auto()  # 즉시값 (0x1234...)

class OperandAccess(Enum):
    READ = auto()
    WRITE = auto()
    READ_WRITE = auto() # ADD EAX, 1 같은 경우 (EAX는 읽고 씀)

class TraceOperand:
    def __init__(self, op_type: OperandType, size: int, value=None, reg_name=None, mem_info=None, access=None, is_implicit=False):
        if access is None:
            access = OperandAccess.READ
        """
        :param op_type: OperandType (REG, MEM, IMM)
        :param size: 바이트 단위 크기 (1, 2, 4, 8)
        :param value: IMM일 경우 실제 값 (int)
        :param reg_name: REG일 경우 레지스터 이름 (str, 'rax', 'eip' 등)
        :param mem_info: MEM일 경우 딕셔너리 {'base': 'rax', 'index': 'rcx', 'scale': 8, 'disp': 0x10}
        """
        self.type = op_type
        self.size = size

        # 값 저장소
        self.imm_value = value      # Immediate Value
        self.reg_name = reg_name    # Register Name
        self.mem_info = mem_info    # Memory Info dict

        self.access = access  # READ / WRITE
        self.is_implicit = is_implicit  # True면 원래 어셈블리엔 없는 것

    def __repr__(self):
        prefix = "[Implicit] " if self.is_implicit else ""
        direction = " (R)" if self.access == OperandAccess.READ else " (W)" if self.access == OperandAccess.WRITE else " (RW)"

        if self.type == OperandType.REG:
            original_repr = f"<Reg: {self.reg_name} ({self.size}B)>"
        elif self.type == OperandType.MEM:
            base = self.mem_info.get('base')
            idx = self.mem_info.get('index')
            scale = self.mem_info.get('scale', 1)
            disp = self.mem_info.get('disp', 0)

            # 주소 표현식 조립
            addr_parts = []

            # 1. Base (있을 경우만)
            if base:
                addr_parts.append(str(base))

            # 2. Index * Scale (Index가 있을 경우만)
            if idx:
                if scale > 1:
                    addr_parts.append(f"{idx}*{scale}")
                else:
                    addr_parts.append(str(idx))

            # 3. Displacement (0이 아닐 경우만)
            if disp != 0:
                # 음수일 경우를 고려하여 부호 처리 (Capstone의 disp는 보통 부호 포함)
                if disp > 0:
                    addr_parts.append(hex(disp))
                else:
                    # 음수일 경우 -0x123 형태로 표현하기 위함
                    addr_parts.append(f"-{hex(abs(disp))}")

            # 리스트에 아무것도 없으면 0으로 표시
            addr_str = " + ".join(addr_parts) if addr_parts else "0"
            # 덧셈 기호가 중복 표시되는 경우(-부호 등)를 위한 후처리 (선택 사항)
            addr_str = addr_str.replace(" + -", " - ")

            original_repr = f"<Mem: [{addr_str}] ({self.size}B)>"
        elif self.type == OperandType.IMM:
            original_repr = f"<Imm: {hex(self.imm_value)} ({self.size}B)>"
        else:
            original_repr = "<Unknown>"

        # 리턴하기 전에 prefix와 direction을 붙여줍니다.
        # 예: [Implicit] <Mem: [esp-4] (4B)> (W)
        return f"{prefix}{original_repr}{direction}"

    # =========================================================================
    # 주소 계산 (Concrete + Symbolic)
    # =========================================================================
    def resolve_addr(self, ctx, current_ip=None):
        """
        이 오퍼랜드가 가리키는 메모리 주소를 계산하여 반환합니다.
        반환값: (concrete_addr, symbolic_addr_expr)
        """
        if self.type != OperandType.MEM:
            return None, None

        # 1. 초기값 (Base)
        conc_addr = 0
        sym_addr_parts = []  # Z3 수식을 만들기 위한 리스트

        # Base Register
        if self.mem_info.get('base'):
            base_reg = self.mem_info['base']
            if base_reg.lower() == 'rip':
                if current_ip is None: raise ValueError("RIP-relative needs IP")
                conc_addr += current_ip
                # RIP는 상수 취급하므로 심볼릭 식에는 추가 안 하거나, 상수로 추가
                sym_addr_parts.append(BitVecVal(current_ip, ctx.arch_mode))
            else:
                c, s, _ = ctx.get_register(base_reg)
                conc_addr += c
                sym_addr_parts.append(s)  # 심볼릭 변수 추가 (Pointer Taint 추적용)

        # Index * Scale
        if self.mem_info.get('index'):
            index_reg = self.mem_info['index']
            scale = self.mem_info.get('scale', 1)

            c, s, _ = ctx.get_register(index_reg)
            conc_addr += (c * scale)

            # 심볼릭 식: index * scale
            # Z3에서 scale은 상수여야 함
            if scale > 1:
                sym_addr_parts.append(s * scale)
            else:
                sym_addr_parts.append(s)

        # Displacement
        if self.mem_info.get('disp'):
            disp = self.mem_info['disp']
            conc_addr += disp
            sym_addr_parts.append(BitVecVal(disp, ctx.arch_mode))

        # 마스킹 (Overflow 처리)
        mask = (1 << ctx.arch_mode) - 1
        final_conc_addr = conc_addr & mask

        # 심볼릭 주소 합성 (Z3 Add)
        if sym_addr_parts:
            # sum(sym_addr_parts)와 같음
            final_sym_addr = sum(sym_addr_parts[1:], sym_addr_parts[0])
            # 필요하다면 여기서도 마스킹(Extract) 처리
        else:
            final_sym_addr = BitVecVal(final_conc_addr, ctx.arch_mode)

        return final_conc_addr, final_sym_addr

    # =========================================================================
    # [Core] Read Value (x64 Compatible)
    # =========================================================================
    def read(self, ctx, current_ip=None):
        """
        Context에서 값을 읽어옵니다.
        :param ctx: TraceContext 인스턴스
        :param current_ip: (x64 필수) RIP 상대 주소 계산을 위한 현재 명령어 주소
        :return: (concrete_val, symbolic_expr)
        """
        if self.type == OperandType.IMM:
            # 즉시값은 항상 상수이므로 Concrete 값과 BitVecVal 반환
            sym = BitVecVal(self.imm_value, self.size * 8)
            return self.imm_value, sym

        elif self.type == OperandType.REG:
            # 레지스터 읽기 (Context가 64/32비트 처리함)
            c, s, _ = ctx.get_register(self.reg_name)
            return c, s

        elif self.type == OperandType.MEM:
            # 1. 주소를 먼저 계산 (여기서 Pointer Taint 여부 확인 가능)
            addr_c, addr_s = self.resolve_addr(ctx, current_ip)

            # 2. 그 주소에 있는 값을 가져옴 (Value Taint)
            val_c, val_s = ctx.get_memory(addr_c, self.size)

            # (선택 사항) 만약 '주소'가 오염되었다면 '값'도 오염된 것으로 간주할 것인가?
            # Taint Policy에 따라 addr_s가 Symbolic이면 val_s도 Taint 시키는 로직을 추가할 수 있음.

            return val_c, val_s

        raise ValueError("Unknown Operand Type")

    # =========================================================================
    # [Core] Write Value (x64 Compatible)
    # =========================================================================
    def write(self, ctx, concrete_val, symbolic_expr, current_ip=None):
        """
        계산된 결과(Concrete + Symbolic)를 Context에 씁니다.
        :param current_ip: 메모리 쓰기 시 주소 계산을 위해 필요할 수 있음
        """
        # Z3 Expression 크기 검증 (안전장치)
        if symbolic_expr is not None:
            expected_bits = self.size * 8
            if symbolic_expr.size() != expected_bits:
                # 크기가 다르면 ZeroExt나 Extract로 맞춰주는 것이 좋으나,
                # 여기서는 디버깅을 위해 경고를 띄우거나 그대로 진행
                pass

        if self.type == OperandType.REG:
            ctx.set_register(self.reg_name, concrete_val, symbolic_expr)

        elif self.type == OperandType.MEM:
            # [변경] _calculate_effective_address 대신 resolve_addr 사용
            # resolve_addr은 (concrete, symbolic)을 반환하므로 [0]번째만 사용
            addr_c, _ = self.resolve_addr(ctx, current_ip)

            ctx.set_memory(addr_c, self.size, concrete_val, symbolic_expr)

        elif self.type == OperandType.IMM:
            raise RuntimeError("Cannot write to Immediate Operand!")


# =============================================================================
# [Factory] Helper to create Operands from Capstone
# 코드 예) Trace Loop
# for line in trace_data:
#     current_ip = line['ip']  # Trace 파일에서 IP 가져오기
#
#     # ... (Capstone 디스어셈블리 수행 -> cs_inst 생성) ...
#     # cs_inst = disas.disasm(code, current_ip)
#
#     # 오퍼랜드 생성 (예: [RIP + 0x1000])
#     op_src = create_operand_from_capstone(cs_inst, cs_inst.operands[1])
#
#     # 값 읽기 (여기서 current_ip를 넘겨주는 것이 핵심!)
#     val_conc, val_sym = op_src.read(ctx, current_ip=current_ip)
#
#     print(f"Read from {op_src}: {hex(val_conc)}")
# =============================================================================
def create_operand_from_capstone(cs_inst, cs_op):
    """
    Capstone Instruction(cs_inst)과 Operand(cs_op)를 받아 TraceOperand 생성
    cs_inst가 필요한 이유: RIP 상대 주소 계산 시 명령어 길이 등이 필요할 수 있음 (선택적)
    """
    # Capstone access 확인
    access = OperandAccess.READ
    if cs_op.access == CS_AC_WRITE:
        access = OperandAccess.WRITE
    elif cs_op.access == CS_AC_READ | CS_AC_WRITE:
        access = OperandAccess.READ_WRITE

    # Size: Capstone은 size 속성을 바이트 단위로 줍니다.
    size = cs_op.size

    # 1. Register Operand
    if cs_op.type == x86.X86_OP_REG:
        # Capstone ID -> String 변환 (외부 함수나 cs.reg_name 필요)
        # 여기서는 cs_inst._cs.reg_name(id)를 사용한다고 가정
        reg_name = cs_inst.reg_name(cs_op.reg)
        return TraceOperand(OperandType.REG, size, reg_name=reg_name, access=access)

    # 2. Immediate Operand
    elif cs_op.type == x86.X86_OP_IMM:
        return TraceOperand(OperandType.IMM, size, value=cs_op.imm, access=access)

    # 3. Memory Operand
    elif cs_op.type == x86.X86_OP_MEM:
        mem = cs_op.mem

        # Register ID to Name conversion
        base_reg = cs_inst.reg_name(mem.base) if mem.base != 0 else None
        index_reg = cs_inst.reg_name(mem.index) if mem.index != 0 else None

        mem_info = {
            'base': base_reg,
            'index': index_reg,
            'scale': mem.scale,
            'disp': mem.disp
        }
        return TraceOperand(OperandType.MEM, size, mem_info=mem_info, access=access)

    return None