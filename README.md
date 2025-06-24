# SARD-vs-CVE
AI가 SARD는 잘 탐지하지만 CVE는 놓치는 이유를 분석하기 위해 두 데이터를 비교합니다.

## 개요

### CWE-134: FSB(Format String Bug)
| CVE            | SW               | 분석 | 교수님 확인 | 교훈                                                         |
|----------------|------------------|------|-------------|--------------------------------------------------------------|
| CVE-2011-4930  | htcondor         | ✅   | ✅          | — |
| CVE-2015-8617  | php (예외처리)   | ✅   | ✅          | 슬라이싱의 종료 지점(Source) 불명확 |
| CVE-2017-12588 | rsyslog          | ❌   | —           | 슬라이스에 메시지 큐(enqueue) ↔ consumer 연결에 대한 표현 방안 필요                 |

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
| CVE-2019-16718~| radare2              | ✅   | ✅     | —                                                            |

## 세부 사항
### CWE-134: FSB(Format String Bug)
#### CVE-2015-8617

php에서 `<?php $name="%n%n%n"; $name::doSomething(); ?>` 실행 시, 존재하지 않는 클래스명($name)으로 인해 예외가 발생한다. 이때 `zend_throw_error()`에서 $name 값을 포맷 문자열로 그대로 사용해 포맷 스트링 취약점이 발생한다.
```c
static void zend_throw_or_error(int fetch_type, zend_class_entry *exception_ce, const char *format, ...) {
    va_list va;
    char *message = NULL;

    va_start(va, format);
    zend_vspprintf(&message, 0, format, va);  // va가 $name이 되고, message에 %n%n이 포함됨

    if (fetch_type & ZEND_FETCH_CLASS_EXCEPTION) {
        zend_throw_error(exception_ce, message); // %n%n이 포함된 message가 포맷 문자열로 그대로 사용됨
    }
}
```

##### 슬라이싱의 종료 지점(Source) 불명확
Source는  
1. "소스코드 파일을 open하는 코드"  
2. `%n%n`과 같은 값을 `zend_fetch_class()`의 인자로 전달하는 코드  
등 여러 방식으로 해석될 수 있음.

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

// Zend/zend_execute_API.c:221
static void zend_throw_or_error(int fetch_type, zend_class_entry *exception_ce, const char *format, ...) {
    ...
}
```

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