# SARD-vs-CVE
AI가 SARD는 잘 탐지하지만 CVE는 놓치는 이유를 분석하기 위해 두 데이터를 비교합니다.

## 개요

...                                                      |

## 세부 사항
### CWE-134: FSB(Format String Bug)
#### CVE-2011-4930
##### 취약점 설명
분산 컴퓨팅 도구 HTCondor에서 입력받은 사용자 계정 정보를 sprintf의 포맷 문자열로 그대로 사용하면서 발생한 포맷 스트링 취약점

```c
/* src/condorr_credd/credd.cpp:266 */
if (!socket->code(name)) {
   if (strchr(name, ':')) {
      owner = strdup(name);
      char *pColon = strchr(owner, ':');
      *pColon = '\0';
      sprintf(name, (char *)(pColon + sizeof(char)));
   }
}
```

##### SARD는 잘 탐지하는데 이 CVE는 탐지 못했던 이유
Joern이 취약점 sink인 sprintf를 노드로 인식하지 못해 슬라이스가 생성되지 않아 취약점 예측이 불가능

#### CVE-2015-8617
##### 취약점 설명
php 인터프리터에서 존재하지 않는 클래스명에 대한 예외 처리 시, 해당 클래스 명을 포맷 문자열로 그대로 사용하면서 발생한 포맷 스트링 취약점
- Source: 사용자 입력한 클래스명
- Sink: source를 포맷으로 사용해 호출되는 `zend_vspprintf()`

PoC 예시: `<?php $name="%n%n%n"; $name::doSomething(); ?>`

```c
// Zend/zend_execute_API.c:1368
zend_class_entry *zend_fetch_class(zend_string *class_name, int fetch_type) {
    ...
    if ((ce = zend_lookup_class_ex(class_name, NULL, 1)) == NULL) {
        ...
        zend_throw_or_error(fetch_type, NULL, "Class '%s' not found", ZSTR_VAL(class_name));
        ...
    }
    return ce;
}

/* Zend/zend_execute_API.c:221 */
static void zend_throw_or_error(int fetch_type, zend_class_entry *exception_ce, const char *format, ...) {
	va_list va;
	char *message = NULL;

	va_start(va, format);
	zend_vspprintf(&message, 0, format, va);
    // message = "Class '%n%n%n' not found"

	if (fetch_type & ZEND_FETCH_CLASS_EXCEPTION) {
		zend_throw_error(exception_ce, message);

/* Zend/zend.c:1313 */
ZEND_API ZEND_COLD void zend_throw_error(zend_class_entry *exception_ce, const char *format, ...) /* {{{ */
{
	va_list va;
	char *message = NULL;
	...
	va_start(va, format);
	zend_vspprintf(&message, 0, format, va);
    // format = "Class '%n%n%n' not found"
```

##### SARD는 잘 탐지하는데 이 CVE는 탐지 못했던 이유

###### 불충분한 슬라이싱 범위
프로그램 슬라이싱은 취약한 코드의 source에서 sink까지의 코드 조각을 추출하는 기술이다.

SARD 데이터셋은 source와 sink가 같은 함수에 있어 단일 함수 슬라이싱으로 취약점이 탐지 가능하다.

그러나 CVE는 source와 sink가 서로 다른 함수에 위치해 interprocedural slicing 없이는 취약 흐름을 포착할 수 없다.

이로 인해 단일 함수 슬라이싱 만으로는 CVE 취약점을 예측할 수 없다.

##### 그 외 불분명한 슬라이싱 범위 문제
Source와 Sink에는 여러 개의 후보가 있을 수 있다.

이로 인해 CVE 취약점 탐지를 위해 슬라이싱 할 때 어느 수준의 범위로 슬라이싱할지 기준이 모호하다.

**Source**
후보 1. 소스코드 파일을 open하는 코드
후보 2. 사용자가 입력한 클래스명을 전달하는 `zend_fetch_class()`함수 호출 코드 

**Sink**
후보 1. source를 포맷으로 사용해 호출되는 `zend_vspprintf()`
후보 2. 최하단에 있는 `vspprintf()`


#### CVE-2017-12588
현재 진행 중(슬라이스에 메시지 큐(enqueue) ↔ consumer 연결에 대한 표현 방안 필요)

### CWE-400: RE(Resource Exhaustion)
#### CVE-2017-11142
PHP가 HTTP POST 본문을 파싱할 때 선형 검색 함수인 memchr()를 과도하게 호출해 리소스 고갈 취약점이 발생할 수 있다.

```c
static zend_bool add_post_var(zval *arr, post_var_data_t *var, zend_bool eof TSRMLS_DC){
	if (var->ptr >= var->end) {
	vsep = memchr(var->ptr, '&', var->end - var->ptr);
```
##### O(n) 함수 반복 호출 맥락 표현에 슬라이스만으로는 부족함, 다시 표현 필요



#### CVE-2019-12973
#### CVE-2018-20784
#### CVE-2019-17351

### CWE-78: OS Command Injection
#### CVE-2017-15108
#### CVE-2017-15924
#### CVE-2018-6791
#### CVE-2018-16863
#### CVE-2019-13638~
#### CVE-2019-16718~



### 1. CVE는 source와 sink 사이의 call stack이 길고, SARD는 짧다.
따라서 slicer가 call stack 전체를 포함하지 못해 SARD는 잘 탐지하지만 CVE는 놓칠 수 있다.

### 2. 

## 개요
### CWE-134: FSB(Format String Bug)
| CVE            | SW               | 분석 | 교수님 확인 | 교훈                                                         |
|----------------|------------------|------|-------------|--------------------------------------------------------------|
| CVE-2011-4930  | htcondor         | ✅   | ✅          | — |
| CVE-2015-8617  | php (예외처리)   | ✅   | ✅          | 슬라이싱의 종료 지점(Source) 불명확 |
| CVE-2017-12588 | rsyslog          | ✅   | ✅           | 슬라이스에 메시지 큐(enqueue) ↔ consumer 연결에 대한 표현 방안 필요                 |

---

### CWE-400: RE(Resource Exhaustion)
| CVE           | SW        | 분석 | 교수님 확인 | 교훈                                                         |
|---------------|-----------|------|-------------|--------------------------------------------------------------|
| CVE-2017-11142| php (post)| ✅   | ✅         | O(n) 함수 반복 호출 맥락 표현에 슬라이스만으로는 부족함, 다시 표현 필요       |
| CVE-2019-12973| openjpeg  | ✅   | ✅         | 깊은 중첩 구조체 → 데이터 흐름 추적이 joern으로 되는지 확인 필요                 |
| CVE-2018-20784| linux     | ❌   | —           | —                                                            |
| CVE-2019-17351| linux     | ❌   | —           | —                                                            |

---

### CWE-78: OS Command Injection
| CVE            | SW                   | 분석 | 교수님 확인 | 교훈                                                         |
|----------------|----------------------|------|-------------|--------------------------------------------------------------|
| CVE-2017-15108 | vd_agent             | ✅   | ❓          | 데이터가 callback 함수로 흘러가는 경우는 함수 간 슬라이싱으로 표현 불가 |
| CVE-2017-15924 | shadowsocks-libev    | ✅   | ❓          | callback + 외부 함수 조합 → 슬라이스 표현 모호               |
| CVE-2018-6791  | plasma-workspace     | ✅   | ✅          | 데이터 흐름이 전역 변수나 객체 속성을 거치는 경우 그리고 클래스 내 set() 메소드를 거치는 경우는 슬라이스로 표현 불가 |
| CVE-2018-16863 | ghostpdl             | ✅   | ✅          | —                                                            |
| CVE-2019-13638~| patch                | ✅   | ✅          | caller≠source, 전역 변수 흐름까지 슬라이싱에 포함해야 함     |
| CVE-2019-16718~| radare2              | ✅   | ✅     | —      