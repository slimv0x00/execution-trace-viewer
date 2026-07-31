# MV Adimeht FISH VM 구조 노트

이 문서는 `mv_adimeht` analyzer가 사용하는 FISH VM의 추상 모델을 기록한다.
trace별 address, offset, opcode 값, row ID 같은 실제 값은 이 문서에 쓰지 않는다.
그런 값은 `docs/mv_adimeht/trace_notes/` 아래의 trace별 노트에 저장한다.

## 범위

이 노트는 현재 analyzer 코드와 분석 과정에서 추론한 working model을 설명한다.
Themida FISH VM의 완전한 명세가 아니다. 여러 sample에서 반복적으로 확인되어
VM 구조 모델 자체가 바뀌는 경우 이 문서를 갱신한다.

관련 구현 파일:

- `plugins/mv_adimeht.py`
- `plugins/TraceAdimehtFISH.py`
- `plugins/TraceAdimehtLightFISH.py`
- `plugins/TraceContext.py`
- `plugins/TraceTaint.py`

현재 주 분석 trace:

- `traces/themida_vm_add_fish_red_v3.0.3.0.trace32`
- Trace note: `docs/mv_adimeht/trace_notes/themida_vm_add_fish_red_v3.0.3.0.md`

## 전체 모델

FISH VM 실행은 host x86 trace 안에서 VM scope에 진입하고, VBR-relative state
block을 조작하고, VM bytecode를 fetch하고, virtual handler를 결정한 뒤, 하나의
virtual instruction 또는 그 일부를 구현하는 host instruction으로 dispatch되는
흐름으로 본다.

Analyzer는 raw host code에서 VM semantics를 한 번에 직접 복구하려고 하지 않는다.
대신 다음 VM-specific storage class들을 통해 data provenance를 추적한다.

- Virtual Bus slot: `VB_...`
- VM bytecode fetch: `VMBLOB_...`
- virtual handler table entry: `VCH_...`
- Virtual Micro OPcode slot: `VMOP_...`
- virtual program counter slot: `VPC_...`
- virtual handler table pointer slot: `VHTP_...`

## 용어

- `VBR`: Virtual Base Register. VM 내부 state와 Virtual Bus slot 접근의 기준이
  되는 base register/base value로 본다.
- `VB`: Virtual Bus. `VB_0x...` label은 `VBR + offset`으로 접근되는 Virtual Bus
  slot을 의미한다.
- `VMOP`: Virtual Micro OPcode. `VMOP_0x...` label은 dispatch cycle에서 decoded
  micro opcode byte를 저장하는 Virtual Bus slot을 의미한다.

## VM Scope

현재 모델은 host `EBP` 값을 VM base register carrier로 본다. 전체 trace에서 가장
자주 등장하는 `EBP` 값을 `VBR`로 탐지한다.

과거 lightweight 모델은 각 row의 `EBP`가 탐지된 `VBR`과 같은지만 보고 VM 내부
여부를 판단했다. 현재 LightFISH는 이 값을 구조적 증거 중 하나로만 사용한다.
VBR-relative access, VHTP-range access, stable `EBP == VBR` row를 모아 VM 구조가
실제로 관측되는 구간을 찾고, 그 앞뒤의 context-save prologue와 restore epilogue를
포함해 `vm_intervals`를 만든다.

구체적으로 entry 쪽은 첫 구조적 증거 이전의 `pushfd/pushf` stack write를 우선
찾고, exit 쪽은 마지막 구조적 증거 이후 `popfd/popf` restore 뒤의 `ret`를 우선
찾는다. 이 full interval은 `[VM]` comment와 UI 표시용으로 쓰고, provenance 추적은
첫 구조적 증거부터 시작하는 `vm_tracking_intervals`를 사용한다. 이렇게 하면 black
계열처럼 `EBP`가 잠시 VBR이 아닌 값으로 바뀌는 VM 진입/탈출 구간도 VM scope로
표시하면서, host register 저장 stub을 VM data-flow로 과하게 seed하지 않을 수 있다.

## VBR And VB Slots

`VBR`은 Virtual Base Register이다. 현재 trace 모델에서는 VM 내부 state와 Virtual
Bus 접근의 기준이 되는 base value로 추적한다. effective address가 `VBR + offset`
형태인 memory access는 Virtual Bus slot으로 모델링한다.

```text
VBR + offset -> VB_0x{offset}
```

일부 `VB_...` slot은 detection 이후 더 구체적인 label을 받는다.

- `VPC_0x...`: virtual program counter slot
- `VHTP_0x...`: virtual handler table pointer slot
- `VMOP_0x...`: Virtual Micro OPcode slot

일반 `VB_...` slot은 Virtual Bus 위의 virtual register, temporary VM state,
dispatch state, handler-local value 등일 수 있다. 추상 label만으로는 정확한
semantics를 확정하지 않고, `VBR` 기준 offset으로 접근되는 Virtual Bus slot이라는
의미만 가진다.

## VPC

`VPC`는 반복적으로 read된 뒤 VM bytecode fetch address처럼 역참조되는
VBR-relative slot으로 본다.

현재 detection heuristic:

- VBR-relative slot의 read/write를 수집한다.
- 각 slot에 대해 read value가 짧은 lookahead 안에서 memory address로 다시
  사용되는 비율을 계산한다.
- pointer-dereference behavior가 가장 강한 slot을 선택한다.

실행 중 `VPC` write는 virtual program counter의 이동으로 annotate한다. arithmetic
write는 가능하면 이전 VPC 값 또는 현재 VPC base 기준의 stride로 해석한다.

`VPC` provenance는 `VPC_...` 자체를 유지하는 것을 기본 정책으로 한다. `ADD
[VPC], offset`처럼 bytecode-derived stride가 사용되더라도 그 stride는 해당 fetch
row에 `vpc stride`로 annotate하고, 업데이트된 VPC 값 안에 계속 살아있는
provenance로 보지 않는다. Program counter는 다음 fetch 위치를 나타내는 cursor에
가깝기 때문에, 과거 offset source를 계속 carry하면 이후 fetch와 VB offset
annotation이 과하게 오염된다.

## VMBLOB

Memory read가 `VPC`-derived address를 사용하면, 접근한 concrete address를 VM
bytecode fetch로 label한다.

```text
VPC-derived read -> VMBLOB_0x{fetch_addr}
```

`VMBLOB_...` label은 provenance marker이다. 어떤 bytecode byte 또는 field가 이후
VM state, handler index 계산, VPC 이동, VMOP assignment, branch decision에
기여했는지 추적하기 위한 이름이다.

Fetch row에는 역방향 annotation이 붙을 수 있다.

- `fetch`
- `vmop`
- `vpc stride`
- `vb offset`
- `vhtp index`
- `vtable offset`

Fetch annotation은 VCH table entry load로 handler selection이 확인될 때까지 유지한다.
VPC arithmetic update는 같은 virtual instruction decode 흐름 안에서 발생할 수
있으므로, VPC가 이동했다는 이유만으로 fetch row mapping을 닫지 않는다. VCH load가
확인되면 해당 fetch row mapping을 닫고, 같은 concrete bytecode address가 나중에
다시 fetch되면 새 dynamic fetch row로 다시 기록한다.

## VHTP And VCH

`VHTP`는 관측된 VPC 값들과 분리된 stable VBR-relative slot으로 본다. 현재 샘플에서는
handler-related indexing의 기준값처럼 사용되며, 고정 code-section 자체라기보다
다음 handler/dispatch 위치를 계산하는 virtual PC 계열 상태값으로 해석한다.

`VHTP`-derived address에서 read가 발생하면 virtual handler table access로
모델링한다.

```text
VHTP + index * entry_size -> VCH_0x{index}
```

`VCH_...` label은 VM bytecode-derived value에 의해 선택된 handler를 추적한다.
`JMP` 또는 `CALL`이 `VCH_...` label을 carry하는 값을 사용하면 analyzer는 그 row를
handler transfer로 annotate한다.

특수 label `VTABLE`은 VHTP-derived index가 concrete handler entry가 아니라 root
table position으로 해석될 때 사용할 수 있다.

## VMOP

`VMOP`는 Virtual Micro OPcode slot이다. Dispatch cycle에서 decoded micro opcode
byte를 저장하는 VBR-relative slot으로 본다.

현재 detection heuristic:

- `VPC`와 `VHTP`는 후보에서 제외한다.
- 반복적인 write가 있어야 한다.
- 관측된 nonzero value가 1 byte 범위에 있어야 한다.
- reads-per-write 비율이 높아야 한다.
- pointer처럼 동작하는 slot은 제외한다.

VM bytecode-derived value가 `VMOP`에 write되면, 그 값에 기여한 fetch row에 opcode
byte를 annotate할 수 있다. 이후 해당 slot의 read와 comparison을 이용해 dispatch
decode point를 탐지한다.

## Dispatch And Decode

현재 모델은 많은 dispatch decision을 comparison 이후 conditional branch가 따라오는
형태로 본다.

Full mode는 다음 정보를 더 정밀하게 추적한다. Light mode도 VMOP slot, VMOP write,
간단한 VMOP-derived decode decision을 annotate할 수 있다.

- 현재 `VMOP`에 기여한 bytecode fetch
- flag-setting instruction 실행 시점에 존재하는 symbolic variable
- 뒤따르는 conditional branch가 VMOP decode match에 해당하는지 여부

Branch condition이 equality match를 의미하면 analyzer는 현재 VMOP value에 대한
decode annotation을 출력할 수 있다.

비-VMOP branch decision도 comparison이 추적 중인 `VB_...` 또는 `VMBLOB_...` 값에서
유래한 경우 annotate할 수 있다.

## Symbolic And Lightweight Modes

Full mode인 `TraceAdimehtFISH`는 `TraceContext`와 `TraceTaint`를 통해 z3-backed
symbolic expression을 사용한다. mixed provenance를 표현하고 더 자세한 관계를
복구할 수 있지만 비용이 더 크다.

Lightweight mode인 `TraceAdimehtLightFISH`는 provenance를 label set으로 추적한다.
빠른 반복 실행과 UI-friendly tracing을 위한 mode이다. 주요 구조 개념은 full mode와
같지만 full symbolic expression은 보존하지 않는다.

두 mode는 적어도 다음 큰 구조에 대해서는 일치해야 한다.

- VM scope
- VBR-relative slot
- VPC fetch source
- VHTP/VCH handler selection
- bytecode-to-state provenance

두 mode가 서로 다른 결과를 내면, sample-specific evidence를 trace별 노트에 먼저
기록한다. 여러 sample에서 패턴이 반복적으로 확인되기 전까지는 이 추상 모델을
바꾸지 않는다.

## Analysis Flow

Analyzer는 현재 대략 다음 순서로 동작한다.

1. Host `EBP`의 dominant value에서 `VBR`을 탐지한다.
2. `VPC`, `VHTP`, full mode의 `VMOP` 같은 special VBR-relative slot을 탐지한다.
   `VPC`는 기본 20-row lookahead로 찾고, black처럼 지연 fetch가 큰 경우에는
   1000-row lookahead fallback을 사용한다.
3. VBR/VHTP/VB 접근과 prologue/epilogue를 이용해 VM interval을 탐지한다.
4. 각 host instruction과 operand를 parse한다.
5. 현재 row가 VM scope 내부인지 판단한다.
6. VBR-relative slot access를 `VB_...` 또는 special slot으로 등록한다.
7. VPC-derived memory read를 `VMBLOB_...` fetch로 등록한다.
8. black 계열에서 `push [VMBLOB]`처럼 fetch payload가 host stack에 먼저 저장되면
   `STACK_0x...` temporary carrier로 등록하고, 이후 stack read/pop에서 다시 register
   또는 VB slot으로 전파한다.
9. Fetch된 bytecode data가 VM slot, VPC movement, VMOP, VHTP indexing, handler
   transfer로 전파되는 흐름을 추적한다.
10. Trace row에 symbolic disassembly와 internal VM event를 annotate한다.
11. UI table에 보여줄 row snapshot을 저장한다.

## Trace별 실제 값

다음 값들은 이 추상 노트가 아니라 trace별 파일에 저장한다.

- 탐지된 `VBR`
- `VPC`, `VHTP`, `VMOP` offset과 concrete address
- `VHTP` concrete value
- 의미가 확인된 주요 `VB_...` slot
- 중요한 `VMBLOB_...` fetch address와 row ID
- handler index와 관측된 transfer row
- decoded VMOP value와 row ID
- 특정 sample에서만 성립하는 assumption

새 sample note를 추가할 때는 `docs/mv_adimeht/trace_notes/TEMPLATE.md`를 사용한다.
