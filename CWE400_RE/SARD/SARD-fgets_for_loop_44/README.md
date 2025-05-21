# 📁 SARD-fgets_for_loop_44

## 🔍 취약점 개요
* **취약점 종류**: [CWE-400](https://cwe.mitre.org/data/definitions/400.html) Resource Exhaustion
* **Source**: `fgets()`를 통한 사용자 입력
* **취약 조건**: 사용자 입력값에 대한 검증 없이 반복문의 반복 횟수로 사용
* **Sink**: for 루프에서 검증되지 않은 카운트 값 사용

## 탐지 결과 요약
* **총 슬라이스**: 4개
* **KSignSlicer 결과**:
  - 취약: 0개
  - 정상: 4개
* **AI 모델 결과**:
  - 취약: 0개
  - 정상: 4개

### 탐지 결과
| 파일명 | 호출 함수 | Source | Sink | idx | CWE-ID | 카테고리 | 기준 | 라인 | 라벨 | 토큰 길이 | 예측 |
|--------|-----------|---------|------|-----|---------|-----------|------|------|------|-----------|------|
| CWE400_Resource_Exhaustion__fgets_for_loop_44.c | CWE400_Resource_Exhaustion__fgets_for_loop_44_bad | False | True | 0 | CWE-400 | CallExpression | fgets | 46 | 0 | 48 | 0 |
| CWE400_Resource_Exhaustion__fgets_for_loop_44.c | CWE400_Resource_Exhaustion__fgets_for_loop_44_bad | False | True | 1 | CWE-400 | CallExpression | atoi | 49 | 0 | 56 | 0 |
| CWE400_Resource_Exhaustion__fgets_for_loop_44.c | goodB2G | False | True | 2 | CWE-400 | CallExpression | fgets | 113 | 0 | 48 | 0 |
| CWE400_Resource_Exhaustion__fgets_for_loop_44.c | goodB2G | False | True | 3 | CWE-400 | CallExpression | atoi | 116 | 0 | 56 | 0 |

## 취약점 세부 사항
### 📁 관련 파일 소개
* `CWE400_Resource_Exhaustion__fgets_for_loop_44.c`: 리소스 소진 취약점을 포함한 테스트 케이스 파일

### ❗️ 취약 코드
**문제점**: 사용자로부터 입력받은 값을 검증 없이 반복문의 반복 횟수로 사용하여 리소스 소진 취약점 발생 가능

#### Source: `CWE400_Resource_Exhaustion__fgets_for_loop_44.c:46-49`
```c
/* 취약점: fgets()를 사용하여 사용자로부터 직접 입력을 받음 */
if (fgets(inputBuffer, CHAR_ARRAY_SIZE, stdin) != NULL)
{
    /* 문자열을 정수로 변환하여 반복 횟수로 사용 */
    count = atoi(inputBuffer);
}
```

#### Sink: `CWE400_Resource_Exhaustion__fgets_for_loop_44.c:24-27`
```c
/* 취약점: 사용자 입력값을 검증 없이 반복문의 반복 횟수로 사용 */
for (i = 0; i < (size_t)count; i++)
{
    /* 리소스를 소비하는 작업 수행 */
    printLine("Hello");
}
```

### ✅ 개선 코드
**개선 방법 1 - 입력값 검증**
**패치 위치**: `CWE400_Resource_Exhaustion__fgets_for_loop_44.c:89-96`

```c
/* 개선사항: 반복 횟수에 대한 유효성 검사 추가 */
if (count > 0 && count <= 20)
{
    /* 검증된 범위 내에서만 반복문 실행 */
    for (i = 0; i < (size_t)count; i++)
    {
        printLine("Hello");
    }
}
```

**개선 방법 2 - 안전한 기본값 사용**
**패치 위치**: `CWE400_Resource_Exhaustion__fgets_for_loop_44.c:77-86`

```c
/* 개선사항: 사용자 입력 대신 안전한 고정값 사용 */
int count;
void (*funcPtr) (int) = goodG2BSink;
/* 초기값 설정 */
count = -1;
/* 안전한 상수값으로 설정 */
count = 20;
funcPtr(count);
```

**개선 방법**:
* 방법 1: 입력값 검증
  - 반복 횟수에 대한 상한값(20)과 하한값(0) 설정
  - 입력값이 유효 범위 내에 있는지 검증 후 반복문 실행
  - 검증되지 않은 사용자 입력을 직접 사용하지 않음

* 방법 2: 안전한 기본값 사용
  - 사용자 입력을 받는 대신 안전한 고정값 사용
  - 컴파일 타임에 결정되는 상수값 활용
  - 입력 검증이 필요 없는 안전한 설계 채택 