# SARD-vs-CVE
AI가 SARD는 잘 탐지하지만 CVE는 놓치는 이유를 분석하기 위해 두 데이터를 비교합니다.

## 개요
| CWE | CVE | 오픈소스SW | 취약점 (소스-싱크) |
| :-- | :-- | :--------- | :----------------- |
|  [**CWE-134 FSB </br> (Format String Bug)**](#cwe-134-fsbformat-string-bug)  | [CVE-2011-4930](#cve-2011-4930) | HTCondor (분산 빅데이터 처리) | **소스**: 소켓으로 받은 악성 지정자 문자열을 </br> **싱크**: 인증 데몬에서 `sprintf` 포맷으로 사용 |
| | [CVE-2015-8617](#cve-2015-8617) | PHP (인터프리터) | **소스**: 존재하지 않는 악성 지정자를 포함한 클래스 이름의 PHP 프로그램 실행, </br> **싱크**: 예외 발생 메시지에 포함된 클래스 이름이 `zend_vspprintf` 포맷에 포함 |
| | [CVE-2017-12588](#cve-2017-12588) | rsyslog (로그 수집) | **소스**: 외부 로그 서버 연결 설정 파일 `description` 필드의 악성 지정자 문자열을 </br> **싱크**: `zsocket_bind`의 포맷으로 지정 |
| [**CWE-400 RE </br> (Resource Exhaustion)**](#cwe-400-reresource-exhaustion) | [CVE-2017-11142](#cve-2017-11142) | PHP (HTTP POST 처리) | **소스**: PHP POST 요청 메시지의 폼 필드/파라미터(키와 값)를 </br> **싱크**: 버그로 인해 반복 스캔하여 CPU 사용량이 100%에 도달하고 서비스 마비 |
| | [CVE-2019-12973](#cve-2019-12973) | OpenJPEG (JPEG 코덱) | **소스**: BMP 파일의 너비와 높이 필드에 실제 그림 크기를 훨씬 상회하도록 지정, </br> **싱크**: 픽셀 처리 시 비정상적인 횟수로 반복문을 수행하여 CPU 자원을 고갈시킴 |
| [**CWE-78 OS CI </br> (OS Command Injection)**](#cwe-78-os-command-injection) | [CVE-2017-15108](#cve-2017-15108) | Spice Vdagent (VM 게스트 에이전트) | **소스**: 호스트에서 게스트 디렉토리로 파일 전송 시 지정한 경로에 쉘 명령어 지정, </br> **싱크**: 이 경로가 포함된 문자열을 `system` 함수로 실행 |
| | [CVE-2017-15924](#cve-2017-15924) | Shadowsocks-libev (암호화 프록시) | **소스**: 서버 추가 시나리오, 쉘 명령어 문자열을 포함시킨 서버 포트/패스워드 JSON의 </br> **싱크**: 필드 (`method`, `port`)로 만든 서버 구동 명령어를 `system`으로 실행 |
| | [CVE-2018-6791](#cve-2018-6791) | KDE Plasma Workspace (장치 관리자) | **소스**: 쉘 명령어가 포함된 USB 드라이브 명, 이 USB 드라이브를 연결하면 </br> **싱크**: 이 드라이브 명과 실행 경로가 합해져서 `KRun::runCommand` 함수로 실행 |
| | [CVE-2018-16863](#cve-2018-16863) | ghostscript (문서 뷰어) | **소스**: 출력 파일 경로에 파이프와 실행할 쉘 명령어(`%pipe%bash`)를 지정 </br> **싱크**: `showpage` 명령으로 출력 작업을 개시하면 `pipe_fopen` 함수를 통해 실행 |
| | [CVE-2019-13638](#cve-2019-13638) | patch (패치 프로그램) | **소스**: `-o` 옵션으로 출력 파일명을 지정할 때 쉘 명령어를 포함시키고, </br> **싱크**: `do_ed_script` 함수에서 `sprintf`로 명령어를 만들어 `execl` 함수로 실행 |
| | [CVE-2019-16718](#cve-2019-16718) | radare2 (바이너리 분석 도구) | **소스**: 심볼명에 `!bash`가 포함된 심볼을 갖는 바이너리 </br> **싱크**: 이 심볼명에 포함된 쉘 명령어가 `cmd_interpret` 함수를 통해 실행 |

## CWE-134: FSB(Format String Bug)
### CVE-2011-4930
#### 취약점 설명
HTCondor의 인증 데몬(credd)에서, 소켓을 통해 수신한 'user:name' 형태의 인증 정보 문자열을 처리할 때, 콜론(`:`) 이후의 문자열을 검증 없이 `sprintf`의 포맷 문자열로 직접 사용하여 발생하는 **포맷 스트링 취약점**

1.  공격자가 HTCondor 인증 데몬(`credd`)에 `:` 구분자와 함께 포맷 스트링 지정자(예: `%s%n`)가 포함된 악의적인 인증 정보 문자열(예: `attacker:%s%s%n`)을 소켓을 통해 전송합니다.

2.  `credd` 데몬은 전송받은 악성 문자열을 `name` 버퍼에 저장하고, `strchr`를 통해 `:` 문자가 포함되어 있는지 확인하여 'user:name' 형식의 분리 처리 로직으로 진입합니다.

3.  코드 내에서 `pColon` 포인터는 원본 문자열의 `:` 위치를 가리키게 되고, `pColon + sizeof(char)` 연산을 통해 `:` 바로 다음, 즉 공격자가 제어하는 포맷 스트링 부분(`%s%s%n`)을 가리키게 됩니다.

4.  **(버그 발생)** `sprintf` 함수가 호출될 때, 3단계에서 얻은 포인터, 즉 **사용자 입력의 일부가 검증 없이 포맷 문자열 인자**로 그대로 전달됩니다.

5.  `sprintf` 함수(Sink)는 전달받은 악성 포맷 문자열을 해석하면서 `%s`, `%n` 등의 지정자를 처리하게 되어, 메모리 정보 유출이나 임의 코드 실행으로 이어질 수 있습니다.

이 CVE 취약점을 유발하는 코드(src/condorr_credd/credd.cpp:266)는 아래와 같다.

```c
int 
get_cred_handler(Service * /*service*/, int /*i*/, Stream *stream) {
  	char * name = NULL;
	...
	ReliSock * socket = (ReliSock*)stream;
	...
	socket->decode();

	if (!socket->code(name)) {
	...
	if (strchr(name, ':')) {
		owner = strdup(name);
		char *pColon = strchr(owner, ':');
		*pColon = '\0';
		sprintf(name, (char *)(pColon + sizeof(char)));
	...
}
```

<details>
<summary>이 코드의 취약점을 표현하는 슬라이스</summary>

```c
/* src/condor_io/stream.cpp:349 */
int 
Stream::code( char	*&s)
{
	switch(_coding){
		case stream_encode:
			return put(s);
		case stream_decode:
			return get(s);

/* src/condorr_credd/credd.cpp:266 */
int 
get_cred_handler(Service * /*service*/, int /*i*/, Stream *stream) {
  	char * name = NULL;
	...
	ReliSock * socket = (ReliSock*)stream;
	...
	socket->decode();

	if (!socket->code(name)) {
	...
	if (strchr(name, ':')) {
		owner = strdup(name);
		char *pColon = strchr(owner, ':');
		*pColon = '\0';
		sprintf(name, (char *)(pColon + sizeof(char)));
	...
}
```

</details>

<details>
<summary><h4 style="display:inline-block">위 슬라이스를 추출하는 것에 대한 어려움</h4></summary>

: Joern이 만든 불완전한 PDG

Joern이 취약점 sink인 sprintf를 노드로 인식하지 못해 슬라이스가 생성되지 않아 취약점 예측이 불가능

: source 기준 함수 사전 정의의 어려움

소스(Source) 함수 사전 정의의 어려움: set 함수 사례
함수 간 슬라이싱을 수행할 때, 분석을 멈출 '소스(Source)' 기준 함수의 사전 정의가 필수적입니다.

하지만 HTCondor의 Stream 클래스에 있는 사용자 정의 set 함수는 외부 입력을 처리함에도 불구하고, 정적 분석 도구가 이를 데이터의 '소스'로 식별하기 어렵습니다. set 함수는 대개 변수 값을 설정하는 데 사용되기 때문에, 정적 분석 도구 입장에서는 데이터를 외부로부터 '가져오는' 소스 함수로 파악하기에는 맥락적 정보가 부족합니다.

</details>

### CVE-2015-8617
#### 취약점 설명
PHP 인터프리터에서 존재하지 않는 클래스를 호출할 때 발생하는 오류 메시지를 생성하는 과정에서, 외부에서 제어 가능한 클래스 이름을 검증 없이 포맷 문자열로 사용하여 발생하는 **포맷 스트링 취약점**

1.  공격자가 존재하지 않는 클래스를 호출하는 PHP 코드를 실행시키고, 해당 클래스의 이름으로 `%n` 등 포맷 스트링 지정자를 포함한 악의적인 문자열을 사용합니다. ([PoC 예시](https://bugs.php.net/bug.php?id=71105): `$name="%n%n"; $name::X();`)

2.  PHP 엔진은 해당 클래스를 찾지 못하고, `zend_fetch_class` 함수 내에서 클래스가 존재하지 않을 때의 오류 처리 로직으로 진입합니다.

3.  `zend_fetch_class`는 `"Class '%s' not found"` 라는 정적인 포맷 문자열과 악성 클래스 이름을 인자로 `zend_throw_or_error` 함수를 호출합니다. 이 함수는 `zend_vspprintf`를 통해 `"Class '%n%n' not found"`와 같은 **1차 결과 문자열(message)을 생성**합니다.

4.  **(버그 발생)** `zend_throw_or_error`는 이어서 3단계에서 생성된 `"Class '%n%n' not found"` 문자열을 **새로운 포맷 문자열 그 자체**로 사용하여 `zend_throw_error` 함수를 호출합니다.

5.  최종적으로 `zend_throw_error` 함수 내부의 `zend_vspprintf`(Sink)가 `"Class '%n%n' not found"`를 포맷 문자열로 해석하면서, 공격자가 삽입한 `%n` 같은 지정자를 처리하게 되어 메모리 쓰기 등 임의 코드 실행으로 이어질 수 있습니다.

이 CVE 취약점을 유발하는 코드(sink:main/spprintf.c:744)는 아래와 같다.
```c
/* main/spprintf.c:744 */
static void xbuf_format_converter(void *xbuf, zend_bool is_char, const char *fmt, va_list ap) /* {{{ */
{
	...
	while (*fmt) {
		if (*fmt != '%') {
			...
		} else {
			...
            switch (*fmt) {
                ...
				case 'n':
					*(va_arg(ap, int *)) = is_char? (int)((smart_string *)xbuf)->len : (int)ZSTR_LEN(((smart_str *)xbuf)->s);
```

<details>
<summary>이 코드의 취약점을 표현하는 슬라이스</summary>

```c
// Zend/zend_execute_API.c:1368
zend_class_entry *zend_fetch_class(zend_string *class_name, int fetch_type) {
    ...
    if ((ce = zend_lookup_class_ex(class_name, NULL, 1)) == NULL) {
        ...
        zend_throw_or_error(fetch_type, NULL, "Class '%s' not found", ZSTR_VAL(class_name));
		// `$name="%n%n"; $name::X();`에서 class_name = %n%n
        ...
}

/* Zend/zend_execute_API.c:221 */
static void zend_throw_or_error(int fetch_type, zend_class_entry *exception_ce, const char *format, ...) {
	va_list va;
	char *message = NULL;

	va_start(va, format);
	zend_vspprintf(&message, 0, format, va); // message = "Class '%n%n' not found"

	if (fetch_type & ZEND_FETCH_CLASS_EXCEPTION) {
		zend_throw_error(exception_ce, message);

/* Zend/zend.c:1313 */
ZEND_API ZEND_COLD void zend_throw_error(zend_class_entry *exception_ce, const char *format, ...) /* {{{ */
{
	va_list va;
	char *message = NULL;
	...
	va_start(va, format);
	zend_vspprintf(&message, 0, format, va); // format = "Class '%n%n' not found"
	...

/* Zend/zend.c:632 */
int zend_startup(zend_utility_functions *utility_functions, char **extensions) /* {{{ */
{
	...
	zend_vspprintf = utility_functions->vspprintf_function;
	...

/* main/main.c:2058 */
int php_module_startup(sapi_module_struct *sf, zend_module_entry *additional_modules, uint num_additional_modules)
{
	zend_utility_functions zuf;
    zuf.vspprintf_function = vspprintf;
	...

/* main/spprintf.c:847 */
PHPAPI size_t vspprintf(char **pbuf, size_t max_len, const char *format, va_list ap) /* {{{ */
{
	smart_string buf = {0};
	...
	xbuf_format_converter(&buf, 1, format, ap);
}

/* main/spprintf.c:744 */
static void xbuf_format_converter(void *xbuf, zend_bool is_char, const char *fmt, va_list ap) /* {{{ */
{
	...
	while (*fmt) {
		if (*fmt != '%') {
			...
		} else {
			...
            switch (*fmt) {
                ...
				case 'n':
					*(va_arg(ap, int *)) = is_char? (int)((smart_string *)xbuf)->len : (int)ZSTR_LEN(((smart_str *)xbuf)->s);
```

</details>

<details>
<summary><h4 style="display:inline-block">위 슬라이스를 추출하는 것에 대한 어려움</h4></summary>

: 함수명이 아닌 라인 단위의 sink
: 사용자 정의 함수가 sink인 경우 문제 발생
: (joern의 pdg에서 위 슬라이스의 경로를 포함하는지 확인 필요) 
	: (joern의 pdg에 경로가 있는 경우, interprocedure call의 길이가 길어서 못찾을 가능성)
	: (joern의 pdg에 경로가 없는 경우, 불완전한 pdg)


##### 불충분한 슬라이싱 범위
프로그램 슬라이싱은 취약한 코드의 source에서 sink까지의 코드 조각을 추출하는 기술이다.

SARD 데이터셋은 source와 sink가 같은 함수에 있어 단일 함수 슬라이싱으로 취약점이 탐지 가능하다.

그러나 CVE는 source와 sink가 서로 다른 함수에 위치해 interprocedural slicing 없이는 취약 흐름을 포착할 수 없다.

이로 인해 단일 함수 슬라이싱 만으로는 CVE 취약점을 예측할 수 없다.
</details>

<details>
<summary><h4 style="display:inline-block">그 외 불분명한 슬라이싱 범위 문제</h4></summary>
Source와 Sink에는 여러 개의 후보가 있을 수 있다.

이로 인해 CVE 취약점 탐지를 위해 슬라이싱 할 때 어느 수준의 범위로 슬라이싱할지 기준이 모호하다.

**Source**
후보 1. 소스코드 파일을 open하는 코드
후보 2. 사용자가 입력한 클래스명을 전달하는 `zend_fetch_class()`함수 호출 코드 

**Sink**
후보 1. source를 포맷으로 사용해 호출되는 `zend_vspprintf()`
후보 2. 최하단에 있는 `vspprintf()`

</details>

### CVE-2017-12588
#### 취약점 설명
내부 시스템 로그를 외부 로그 서버로 전송하는 rsyslog에서 ZeroMQ 연결 시, 외부 설정 파일에 있던 메시지 큐 연결 정보가 포맷 문자열로 그대로 사용되어 발생한 **포맷 스트링 취약점**

1. 공격자는 rsyslog 설정 파일(.conf)의 omzmq3 모듈 설정에서, 'description' 파라미터 값으로 %n 등 포맷 스트링 지정자를 포함한 악의적인 문자열을 삽입합니다.
	
	<details>
	<summary><strong>악성 설정 파일 예시 </strong></summary>
	관련 출처: https://www.rsyslog.com/quick-guide-to-omzmq3

    ```conf
	# 공격자는 description에 포맷 스트링 지정자를 삽입합니다.
	*.* action(type="omzmq3"
			sockType="PUB"
			action="BIND"
			description="%n%n%n" 
			template="any_message_template")
    ```
	
	</details>
2. rsyslogd 데몬이 시작되면서 위 설정 파일을 파싱합니다. omzmq3 모듈의 newActInst 함수가 호출되고, 공격자가 삽입한 악성 문자열("%n%n%n")은 아무런 검증이나 처리 없이 그대로 pData->description 필드에 저장됩니다.
3. 이후, 위에서 설정한 action을 통해 실제 로그 메시지를 전송해야 하는 상황이 되면(예: ZMQ 메시지 수신), doAction 함수가 호출됩니다.
4. doAction 함수는 ZMQ 소켓 연결이 아직 초기화되지 않은 것을 확인하고 연결을 시도합니다. 이 과정에서 2단계에서 저장해 두었던 pData->description 문자열("%n%n%n")을 소켓 연결을 위한 주소 문자열로 사용하기 위해 zsocket_bind 함수에 전달합니다.
5. 최종적으로 zsocket_bind 함수 내부의 printf 계열 함수(Sink)가 pData->description 값을 일반 문자열이 아닌 포맷 문자열 그 자체로 해석하여 처리합니다. 이로 인해 공격자가 삽입한 %n 지정자가 실행되면서 메모리 쓰기가 발생하고, 임의 코드 실행으로 이어질 수 있습니다.

이 CVE 취약점을 유발하는 코드(sink:contrib/omzmq3/omzmq3.c:245)는 아래와 같다.
```c
static rsRetVal initZMQ(instanceData* pData) {
    ...
    if (pData->action == ACTION_BIND) {
        if(-1 == zsocket_bind(pData->socket, (char*)pData->description)) {
        // CZMQ_EXPORT int zsocket_bind(void *self, const char *format, ...); @czmq.h
```
<details>
<summary><strong>이 코드의 취약점을 표현하는 슬라이스</strong></summary>

<details>
<summary>설정 파일 파싱</summary>

```c
/* rsyslogd.c:1407 */
DEFobjCurrIf(rsconf) // static rsconf_if_t rsconf = { .ifVersion = 0, .ifIsLoaded = 0 };
rsconf_t *ourConf = NULL;
uchar *ConfFile = (uchar*) "/etc/rsyslog.conf";

static void
initAll(int argc, char **argv)
{
	...
	localRet = rsconf.Load(&ourConf, ConfFile);

/* runtime/rsconf.c:1391 */
BEGINobjQueryInterface(rsconf)
/*
rsRetVal rsconfQueryInterface(rsconf_if_t *pIf); 
rsRetVal rsconfQueryInterface(rsconf_if_t *pIf) {
	rsRetVal iRet = RS_RET_OK;
*/
CODESTARTobjQueryInterface(rsconf)
	...
	pIf->Load = load;

/* runtime/rsconf.c:1321 */
static rsRetVal
load(rsconf_t **cnf, uchar *confFile)
{
	...
	/* open the configuration file */
	r = cnfSetLexFile((char*)confFile);
	if(r == 0) {
		r = yyparse();

/* 
아래와 같은 설정 파일이 파싱된다면
.* action(type="omzmq3" sockType="PUB" action="BIND" description="tcp://:11514" template="any_message_template")

// grammar/lexer.l:242
"action"[ \n\t]*"("		{ BEGIN INOBJ; return BEGIN_ACTION; }

// grammar/grammar.y:195
s_act:	  BEGIN_ACTION nvlst ENDOBJ	{ $$ = cnfstmtNewAct($2); }
// 설정 파일 내용에서 action 키워드와 소괄호 사이에 있는 key와 value 쌍의 리스트를 nvlst로 만든 것이 $2이다. 
*/

/* rainerscript.c:3474 */
struct cnfstmt *
cnfstmtNewAct(struct nvlst *lst)
{
	struct cnfstmt* cnfstmt;
	...
	localRet = actionNewInst(lst, &cnfstmt->d.act);

/* action.c:1980 */
rsRetVal
actionNewInst(struct nvlst *lst, action_t **ppAction)
{
	...
	omodStringRequest_t *pOMSR;
	void *pModData;
	action_t *pAction;
	DEFiRet;

	paramvals = nvlstGetParams(lst, &pblk, NULL);
	...
	cnfModName = (uchar*)es_str2cstr(paramvals[cnfparamGetIdx(&pblk, ("type"))].val.d.estr, NULL);
	if((pMod = module.FindWithCnfName(loadConf, cnfModName, eMOD_OUT)) == NULL) {
		...
	CHKiRet(pMod->mod.om.newActInst(cnfModName, lst, &pModData, &pOMSR)); //pModData 채우기

/* omzmq3.c:380 */
BEGINnewActInst
/*
static rsRetVal newActInst(uchar __attribute__((unused)) *modName, struct nvlst __attribute__((unused)) *lst, void **ppModData, omodStringRequest_t **ppOMSR){  
	rsRetVal iRet = RS_RET_OK; 
	instanceData *pData = ((void *)0); 
	*ppOMSR = ((void *)0);
*/
	struct cnfparamvals *pvals;
	int i;
CODESTARTnewActInst
	if ((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
	...
	for (i = 0; i < actpblk.nParams; ++i) {
		...
		if (!strcmp(actpblk.descr[i].name, "description")) {
			pData->description = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
				// 문제가 되는 description이 여기서 설정됨.
	...
	CODE_STD_FINALIZERnewActInst
	/*
finalize_it: 
	if(iRet == RS_RET_OK || iRet == RS_RET_SUSPENDED) { 
		*ppModData = pData; 
	} else { 
	 	if(*ppOMSR != ((void *)0)) { 
			OMSRdestruct(*ppOMSR); 
			*ppOMSR = ((void *)0); 
		} 
		if(pData != ((void *)0)) { 
			freeInstance(pData); 
		} 
	}
	*/
	...

/* action.c:1982 */
rsRetVal
actionNewInst(struct nvlst *lst, action_t **ppAction)
{
	...
	CHKiRet(pMod->mod.om.newActInst(cnfModName, lst, &pModData, &pOMSR));

	// newActInst() 에서 채운 pModData 가지고 addAction()!
	if((iRet = addAction(&pAction, pMod, pModData, pOMSR, paramvals, lst)) == RS_RET_OK) { 

/* action.c:1903 */
rsRetVal
addAction(action_t **ppAction, modInfo_t *pMod, void *pModData,
	  omodStringRequest_t *pOMSR, struct cnfparamvals *actParams,
	  struct nvlst * const lst)
{
	...
	action_t *pAction;
	...
	pAction->pMod = pMod;
	pAction->pModData = pModData;

	CHKiRet(actionConstructFinalize(pAction, lst));

/* action.c:509 */
rsRetVal
actionConstructFinalize(action_t *__restrict__ const pThis, struct nvlst *lst)
{
	...
	CHKiRet(qqueueConstruct(&pThis->pQueue, cs.ActionQueType, 1, cs.iActionQueueSize,
					processBatchMain));

```
</details>

<details>
<summary>메시지 큐에 메시지가 수신 된 후</summary>

```c
/* runtime/wti.c:365 */
rsRetVal
wtiWorker(wti_t *__restrict__ const pThis)
{
	...
	while(1) { /* loop will be broken below */
		...
		/* try to execute and process whatever we have */
		localRet = pWtp->pfDoWork(pWtp->pUsr, pThis);
		
/* runtime/obj-types.h:139 */
#define DEFpropSetMethFP(obj, prop, dataType)\
	rsRetVal obj##Set##prop(obj##_t *pThis, dataType)\ 
	// rsRetVal  wtpSetpfDoWork(wtp_t *pThis, rsRetVal(*pVal)(void*, void*))
	{ \
		pThis->prop = pVal; \ // pThis->pfDoWork = pVal
		return RS_RET_OK; \
	}

/* runtime/wtp.c:531 */
DEFpropSetMethFP(wtp, pfDoWork, rsRetVal(*pVal)(void*, void*))

/* runtime/queue.c:2405 */
rsRetVal
qqueueStart(qqueue_t *pThis) /* this is the ConstructionFinalizer */
{
	...

	CHKiRet(wtpSetpfDoWork		(pThis->pWtpReg, (rsRetVal (*)(void *pUsr, void *pWti)) ConsumerReg));

/* runtime/queue.c:2005 */
static rsRetVal
ConsumerReg(qqueue_t *pThis, wti_t *pWti)
{
	...
	iRet = DequeueForConsumer(pThis, pWti, &skippedMsgs);
	...
	CHKiRet(pThis->pConsumer(pThis->pAction, &pWti->batch, pWti));

// runtime/queue.c:1374
rsRetVal qqueueConstruct(qqueue_t **ppThis, queueType_t qType, int iWorkerThreads,
	int iMaxQueueSize, rsRetVal (*pConsumer)(void*, batch_t*, wti_t*))

// action.c:509
rsRetVal
actionConstructFinalize(action_t *__restrict__ const pThis, struct nvlst *lst)
{
	...
	CHKiRet(qqueueConstruct(&pThis->pQueue, cs.ActionQueType, 1, cs.iActionQueueSize,
					processBatchMain));

/* action.c:1416 */
static rsRetVal
processBatchMain(void *__restrict__ const pVoid,
	batch_t *__restrict__ const pBatch,
	wti_t *__restrict__ const pWti)
{
	...
	for(i = 0 ; i < batchNumMsgs(pBatch) && !*pWti->pbShutdownImmediate ; ++i) {
		if(batchIsValidElem(pBatch, i)) {
			processMsgMain(pAction, pWti, pBatch->pElem[i].pMsg, &ttNow);

/* action.c:1382 */
static rsRetVal
processMsgMain(action_t *__restrict__ const pAction,
	wti_t *__restrict__ const pWti,
	smsg_t *__restrict__ const pMsg,
	struct syslogTime *ttNow)
{
	...
	iRet = actionProcessMessage(pAction,
				    pWti->actWrkrInfo[pAction->iActionNbr].p.nontx.actParams,
				    pWti);

/* action.c:1171 */
static rsRetVal actionProcessMessage(action_t * const pThis, void *actParams, wti_t * const pWti)
{
	...
	if(getActionState(pWti, pThis) == ACT_STATE_ITX)
		CHKiRet(actionCallDoAction(pThis, actParams, pWti));

/* action.c:1128 */
static rsRetVal actionCallDoAction(action_t *__restrict__ const pThis, 	actWrkrIParams_t *__restrict__ onst iparams, wti_t *__restrict__ const pWti) {
	...
	iRet = pThis->pMod->mod.om.doAction(param,
				            pWti->actWrkrInfo[pThis->iActionNbr].actWrkrData);

/* contrib/omzmq3/omzmq3.c:359 */
BEGINdoAction
/*
runtime/module-template.h:280

#define BEGINdoAction \
static rsRetVal doAction(void * pMsgData, wrkrInstanceData_t __attribute__((unused)) *pWrkrData)\
{\
	uchar **ppString = (uchar **) pMsgData; \
	DEFiRet;
*/
	instanceData *pData = pWrkrData->pData;
CODESTARTdoAction
	pthread_mutex_lock(&mutDoAct);
	iRet = writeZMQ(ppString[0], pData);

/* contrib/omzmq3/omzmq3.c:268 */
rsRetVal writeZMQ(uchar* msg, instanceData* pData) {
	...
    if(NULL == pData->socket)
		CHKiRet(initZMQ(pData));

/* contrib/omzmq3/omzmq3.c:245 */
static rsRetVal initZMQ(instanceData* pData) {
    ...
    if (pData->action == ACTION_BIND) {
        if(-1 == zsocket_bind(pData->socket, (char*)pData->description)) {
        // CZMQ_EXPORT int zsocket_bind(void *self, const char *format, ...); @czmq.h

```

</details>

</details>

<details>
<summary><h4 style="display:inline-block">위 슬라이스를 추출하는 것에 대한 어려움</h4></summary>

: nodes.csv에서 wtpSetpfDoWork 함수가 존재하는지 확인

##### 설정 파일 파서(Parser) 분석의 한계
Ksign 슬라이서와 같은 C/C++ 코드 기반 정적 분석 도구는 .l, .y 파일과 연계된 파서의 동작을 해석하지 못하는 한계를 가집니다. 이로 인해, CVE-2017-12588과 같이 외부 설정 파일에서 시작되어 파서의 콜백 함수를 통해 C 코드로 데이터가 유입되는 유형의 취약점은 데이터 흐름의 시작점을 놓치게 되어 탐지하지 못합니다. 이는 SARD 데이터셋처럼 순수 C 코드로만 구성된 환경에서는 드러나지 않는 문제입니다.


##### 복잡한 매크로!
CVE 코드에서는 DEFpropSetMethFP와 같은 매크로가 함수를 동적으로 생성합니다. wtpSetpfDoWork라는 핵심 함수는 개발자가 직접 작성한 것이 아니라, 매크로와 ## 연산자에 의해 **전처리(Pre-processing) 과정에서 만들어지는 '가상의 함수'**입니다.

정적 분석기는 소스 코드에서 wtpSetpfDoWork 함수의 정의를 찾지 못해 호출 관계(Call Graph)를 구성하는 데 실패합니다. 호출 관계가 끊어지면, 이 함수 내부에서 일어나는 핵심 데이터 흐름(콜백 함수 주소 할당) 또한 추적할 수 없게 됩니다. 결과적으로, 소스(Source)와 싱크(Sink)를 잇는 슬라이스가 중간에 완전히 끊어져 취약점을 탐지할 수 없습니다.


##### 실행 단계가 분리되어 있어 취약점을 하나의 슬라이스로 표현 불가능
실행 단계 분리로 인한 탐지 실패 요약
정적 분석기가 이 취약점을 탐지하지 못하는 이유는, 데이터가 오염되는 시점과 사용되는 시점이 완전히 분리되어 있기 때문입니다.

1단계 (저장): 프로그램이 시작될 때, 악의적인 설정값(Source)은 특정 데이터 구조체에 담겨 메모리(액션 큐)에 저장됩니다.

2단계 (사용): 이후 프로그램이 실행 중일 때, 별개의 워커 스레드가 큐에서 이 데이터를 꺼내와 취약한 함수(Sink)에서 사용합니다.

정적 분석기는 이렇게 시간과 실행 흐름(스레드)이 단절된 '저장' 시점과 '사용' 시점을 하나의 연속된 데이터 흐름으로 연결하지 못합니다. 데이터가 큐에 들어갔다가 나오는 복잡한 과정을 추적하지 못해, 결국 Source와 Sink를 잇는 분석 경로(Slice)가 중간에 끊어지므로 취약점을 놓치게 됩니다.
</details>

<details>
<summary><h4 style="display:inline-block">그 외 CPG(Code Property Graph)로 표현 불가능한 콜백 함수 호출</h4></summary>

이건 SARD도 탐지하지 못하는 사례

**SARD Test Case Flow Variants 44 and 65**
Data passed as an argument from one function to a function in
the same source file called via a function pointer

</details>

## CWE-400: RE(Resource Exhaustion)
### CVE-2017-11142
PHP가 POST 요청을 처리하는 add_post_vars 함수에서, 처리된 데이터의 위치가 올바르게 갱신되지 않아, memchr 함수가 이미 스캔한 데이터를 포함한 전체 버퍼를 반복적으로 재검색하여 CPU **자원을 고갈시키는 서비스 거부(DoS) 취약점**

1. PHP 엔진이 HTTP POST 요청을 받아 php_std_post_handler 함수를 호출합니다. 이 함수는 while 루프를 돌며 POST 데이터를 청크(chunk) 단위로 읽어 post_data 버퍼에 추가합니다.
2. php_std_post_handler는 루프를 돌 때마다 add_post_vars 함수를 호출하여 버퍼에 쌓인 데이터의 변수 파싱을 시도합니다.
3. (버그 발생) 하지만 add_post_var 함수는 호출될 때마다 처리 위치 포인터(var->ptr)를 항상 버퍼의 맨 처음(var->str.c)으로 초기화합니다. 이로 인해 이전에 파싱을 시도했던 부분을 기억하지 못하고, 매번 누적된 데이터 전체를 새로 파싱하게 됩니다.
4. add_post_vars 내부에서 호출되는 add_post_var 함수는 변수 구분자인 &를 찾기 위해 memchr를 사용합니다. 버그로 인해 memchr는 이전에 이미 & 문자가 없음을 확인했던 영역까지 포함하여, 점점 커지는 전체 버퍼를 처음부터 끝까지 반복적으로 스캔하게 됩니다.
5. 공격자는 & 문자 없이 매우 큰 단일 변수(예: a=AAAA...)를 전송하여 이 시나리오를 유발합니다. 버퍼가 계속 커지고(8KB, 16KB, 24KB...) memchr의 스캔 범위가 그에 따라 선형적으로 증가하면서, CPU 사용량이 100%에 도달해 서비스가 마비됩니다. 변수가 하나이므로 max_input_vars 제한은 쉽게 우회됩니다.

[출처](https://bugs.php.net/bug.php?id=73807)에 따르면, 아래와 같이 10000000 글자를 post로 보내면 50,71s 시간이 소요된다고 합니다. // 근데 FreeBSD에서만 발생하는 것으로 봐서는 php 코드 문제인지 의문이 듭니다.
```php
<form method="post">
	<input type="hidden" name="data" value="<?php echo substr($base64, 0, 10000000); ?>">
	<button>SEND</button>
</form>
```
with 10000000 characters the time is as follows:
FreeBSD - 50,71s
Ubuntu/Linux - 100ms


이 CVE 취약점을 유발하는 코드(sink:main/php_variables.c:253, memset)는 아래와 같다.
```
static zend_bool add_post_var(zval *arr, post_var_data_t *var, zend_bool eof TSRMLS_DC){
	if (var->ptr >= var->end) {
	vsep = memchr(var->ptr, '&', var->end - var->ptr);
```
<details>
<summary>이 코드의 취약점을 표현하는 슬라이스</summary>

```c
/* main/php_variables.c:335 */
SAPI_API SAPI_POST_HANDLER_FUNC(php_std_post_handler) {
    zval *arr = (zval *) arg;
    php_stream *s = SG(request_info).request_body;
    post_var_data_t post_data;

    if (s && SUCCESS == php_stream_rewind(s)) {
        memset(&post_data, 0, sizeof(post_data));

        while (!php_stream_eof(s)) { // 반복
            char buf[SAPI_POST_HANDLER_BUFSIZ] = {0};
            size_t len = php_stream_read(s, buf, SAPI_POST_HANDLER_BUFSIZ);

            if (len && len != (size_t) -1) {
                smart_str_appendl(&post_data.str, buf, len);

                if (SUCCESS != add_post_vars(arr, &post_data, 0 TSRMLS_CC)) {
                    ...
				}
            }

            ...
        }

        ...
    }
}

/* main/php_variables.c:298 */
static inline int add_post_vars(zval *arr, post_var_data_t *vars, zend_bool eof TSRMLS_DC) {
    uint64_t max_vars = PG(max_input_vars);

    vars->ptr = vars->str.c;
    vars->end = vars->str.c + vars->str.len;

    while (add_post_var(arr, vars, eof TSRMLS_CC)) {
        if (++vars->cnt > max_vars) {
            php_error_docref(NULL TSRMLS_CC, E_WARNING,
                "Input variables exceeded %" PRIu64 ". "
                "To increase the limit change max_input_vars in php.ini.",
                max_vars);
            return FAILURE;
        }
    }

    if (!eof) {
        memmove(vars->str.c, vars->ptr, vars->str.len = vars->end - vars->ptr);
    }
    return SUCCESS;
}

/* main/php_variables.c:253 */
static zend_bool add_post_var(zval *arr, post_var_data_t *var, zend_bool eof TSRMLS_DC) {
    char *ksep, *vsep, *val;

    if (var->ptr >= var->end) {
        vsep = memchr(var->ptr, '&', var->end - var->ptr);
        if (!vsep) {
            if (!eof) {
                return 0;
            }
        }
    }
    return 1;
}
```

</details>

<details>
<summary><h4 style="display:inline-block">위 슬라이스를 추출하는 것에 대한 어려움</h4></summary>

#### 템플릿: 비정형적 Sink
SARD의 strcpy 같은 명백한 위험 함수와 달리, CVE의 Sink는 평소에 안전한 memchr 함수입니다. 분석기는 단순히 함수 호출을 넘어, '반복문 내에서 비정상적으로 사용되는 패턴' 자체를 이해해야만 자원 고갈(DoS) 취약점으로 인지할 수 있습니다.

#### 템플릿: 상태 기반 버그
SARD는 보통 단일 행위로 문제가 발생하지만, CVE는 여러 번의 루프를 거치며 데이터 구조체의 상태가 계속 변하고 누적되어야 버그가 발생합니다. 분석기는 이처럼 시간에 따른 상태 변화를 추적해야 하는 어려움이 있습니다.

#### 템플릿: 복잡한 함수 간 루프 구조
이 CVE는 외부 함수의 루프가 내부 함수의 논리적 버그를 반복적으로 트리거하는 구조입니다. 각 함수를 독립적으로 분석해서는 찾을 수 없고, 여러 함수에 걸친 루프의 상호작용까지 분석해야 하므로 탐지 난이도가 매우 높습니다.
</details>

### CVE-2019-12973
OpenJPEG의 이미지 변환 기능에서, 조작된 BMP 파일의 너비(width)와 높이(height) 값으로 인해 JPEG2000 인코딩 과정 중 비정상적으로 큰 반복문을 수행하게 되어 CPU **자원을 고갈시키는 서비스 거부(DoS) 취약점**

1.  사용자가 OpenJPEG의 이미지 변환 기능(`convertbmp.c`)을 사용하여 특수하게 조작된 BMP 이미지 파일을 JPEG2000 형식으로 변환을 시도합니다.
2.  변환기는 BMP 파일의 헤더를 읽어 이미지의 너비(width)와 높이(height) 값을 가져옵니다. 공격자는 이 필드에 비정상적으로 매우 큰 값을 설정해 둡니다.
3.  변환기는 읽어들인 너비와 높이 값에 대한 유효성을 제대로 검증하지 않은 채, 이 값을 JPEG2000 인코딩 라이브러리 함수(`opj_t1_encode_cblks` 등)에 전달하여 인코딩 파라미터를 설정합니다.
4.  `opj_t1_encode_cblks` 함수 내의 깊은 중첩 반복문에서, 조작된 너비/높이 값으로부터 계산된 precinct의 너비(`prc->cw`)와 높이(`prc->ch`)가 루프의 종료 조건으로 사용됩니다.
5.  `prc->cw * prc->ch`의 결과가 수십억에 달하는 매우 큰 값이 되어, `for (cblkno = 0; cblkno < prc->cw * prc->ch; ++cblkno)` 루프가 사실상 무한히 반복됩니다. 이로 인해 CPU 사용량이 100%에 도달하여 시스템이 응답 불능 상태에 빠집니다.

이 CVE 취약점을 유발하는 코드(sink:src/lib/openjp2/t1.c:2137, `for (cblkno = 0; cblkno < prc->cw * prc->ch; ++cblkno)`)는 아래와 같다.
`prc->cw`와 `prc->ch`는 `uint32_t` 타입이므로, `prc->cw * prc->ch`의 결과도 최대 4,294,967,295까지 커질 수 있어, 이만큼 반복이 발생할 수 있다.

```c
OPJ_BOOL opj_t1_encode_cblks(opj_t1_t *t1,
                             opj_tcd_tile_t *tile,
                             opj_tcp_t *tcp,
                             const OPJ_FLOAT64 * mct_norms,
                             OPJ_UINT32 mct_numcomps
                            )
{
    OPJ_UINT32 compno, resno, bandno, precno, cblkno;

    tile->distotile = 0;        /* fixed_quality */

    for (compno = 0; compno < tile->numcomps; ++compno) {
        opj_tcd_tilecomp_t* tilec = &tile->comps[compno];
        opj_tccp_t* tccp = &tcp->tccps[compno];
        OPJ_UINT32 tile_w = (OPJ_UINT32)(tilec->x1 - tilec->x0);

        for (resno = 0; resno < tilec->numresolutions; ++resno) {
            opj_tcd_resolution_t *res = &tilec->resolutions[resno];

            for (bandno = 0; bandno < res->numbands; ++bandno) {
                opj_tcd_band_t* OPJ_RESTRICT band = &res->bands[bandno];
                OPJ_INT32 bandconst;

                /* Skip empty bands */
                if (opj_tcd_is_band_empty(band)) {
                    continue;
                }

                bandconst = 8192 * 8192 / ((OPJ_INT32) floor(band->stepsize * 8192));
                for (precno = 0; precno < res->pw * res->ph; ++precno) {
                    opj_tcd_precinct_t *prc = &band->precincts[precno];

                    for (cblkno = 0; cblkno < prc->cw * prc->ch; ++cblkno) {
```

<details>
<summary>이 코드의 취약점을 표현하는 슬라이스</summary>

```c
/* src/bin/jp2/opj_compress.c:2016 */
int main(int argc, char **argv)
{

    opj_cparameters_t parameters;   /* compression parameters */

    opj_stream_t *l_stream = 00;
    opj_codec_t* l_codec = 00;
    opj_image_t *image = NULL;
    raw_cparameters_t raw_cp;
    OPJ_SIZE_T num_compressed_files = 0;

    char indexfilename[OPJ_PATH_LEN];   /* index file name */

    unsigned int i, num_images, imageno;
    img_fol_t img_fol;
    dircnt_t *dirptr = NULL;

    int ret = 0;

    OPJ_BOOL bSuccess;
    OPJ_BOOL bUseTiles = OPJ_FALSE; /* OPJ_TRUE */
    OPJ_UINT32 l_nb_tiles = 4;
    OPJ_FLOAT64 t = opj_clock();

    /* set encoding parameters to default values */
    opj_set_default_encoder_parameters(&parameters);

    /* Initialize indexfilename and img_fol */
    *indexfilename = 0;
    memset(&img_fol, 0, sizeof(img_fol_t));

    /* raw_cp initialization */
    raw_cp.rawBitDepth = 0;
    raw_cp.rawComp = 0;
    raw_cp.rawComps = 0;
    raw_cp.rawHeight = 0;
    raw_cp.rawSigned = 0;
    raw_cp.rawWidth = 0;

    /* parse input and get user encoding parameters */
    parameters.tcp_mct = (char)
                         255; /* This will be set later according to the input image or the provided option */
    if (parse_cmdline_encoder(argc, argv, &parameters, &img_fol, &raw_cp,
                              indexfilename, sizeof(indexfilename)) == 1) {

    /* Read directory if necessary */
    if (img_fol.set_imgdir == 1) {
        num_images = get_num_images(img_fol.imgdirpath);
        dirptr = (dircnt_t*)malloc(sizeof(dircnt_t));
        if (dirptr) {
            dirptr->filename_buf = (char*)malloc(num_images * OPJ_PATH_LEN * sizeof(
                    char)); /* Stores at max 10 image file names*/
            dirptr->filename = (char**) malloc(num_images * sizeof(char*));
            if (!dirptr->filename_buf) {
            for (i = 0; i < num_images; i++) {
                dirptr->filename[i] = dirptr->filename_buf + i * OPJ_PATH_LEN;
            }
        }
        if (load_images(dirptr, img_fol.imgdirpath) == 1) {
        if (num_images == 0) {
    } else {
        num_images = 1;
    }
    /*Encoding image one by one*/
    for (imageno = 0; imageno < num_images; imageno++) {
        image = NULL;
        fprintf(stderr, "\n");

        if (img_fol.set_imgdir == 1) {
            if (get_next_file((int)imageno, dirptr, &img_fol, &parameters)) {
                fprintf(stderr, "skipping file...\n");
                continue;
            }
        }

        switch (parameters.decod_format) {
        case PGX_DFMT:
            break;
        case PXM_DFMT:
            break;
        case BMP_DFMT:
            break;
        case TIF_DFMT:
            break;
        case RAW_DFMT:
            break;
        case RAWL_DFMT:
            break;
        case TGA_DFMT:
            break;
        case PNG_DFMT:
            break;
        default:
            fprintf(stderr, "skipping file...\n");
            continue;
        }

        /* decode the source image */
        /* ----------------------- */

        switch (parameters.decod_format) {
        case PGX_DFMT:
            image = pgxtoimage(parameters.infile, &parameters);
            if (!image) {
            break;

        case PXM_DFMT:
            image = pnmtoimage(parameters.infile, &parameters);
            if (!image) {
            break;

        case BMP_DFMT:
            image = bmptoimage(parameters.infile, &parameters);
            
                /* src/lib/openjp2/openjpeg.c:819 */
                opj_image_t* bmptoimage(const char *filename, opj_cparameters_t *parameters)
                {
                    opj_image_cmptparm_t cmptparm[4];   /* maximum of 4 components */
                    OPJ_UINT8 lut_R[256], lut_G[256], lut_B[256];
                    OPJ_UINT8 const* pLUT[3];
                    opj_image_t * image = NULL;
                    FILE *IN;
                    OPJ_BITMAPFILEHEADER File_h;
                    OPJ_BITMAPINFOHEADER Info_h;
                    OPJ_UINT32 i, palette_len, numcmpts = 1U;
                    OPJ_BOOL l_result = OPJ_FALSE;
                    OPJ_UINT8* pData = NULL;
                    OPJ_UINT32 stride;

                    pLUT[0] = lut_R;
                    pLUT[1] = lut_G;
                    pLUT[2] = lut_B;

                    IN = fopen(filename, "rb");
                    if (!IN) {

                    if (!bmp_read_file_header(IN, &File_h)) {
                    if (!bmp_read_info_header(IN, &Info_h)) {

                    /* Load palette */
                    if (Info_h.biBitCount <= 8U) {
                        memset(&lut_R[0], 0, sizeof(lut_R));
                        memset(&lut_G[0], 0, sizeof(lut_G));
                        memset(&lut_B[0], 0, sizeof(lut_B));

                        palette_len = Info_h.biClrUsed;
                        if ((palette_len == 0U) && (Info_h.biBitCount <= 8U)) {
                            palette_len = (1U << Info_h.biBitCount);
                        }
                        if (palette_len > 256U) {
                            palette_len = 256U;
                        }
                        if (palette_len > 0U) {
                            OPJ_UINT8 has_color = 0U;
                            for (i = 0U; i < palette_len; i++) {
                                lut_B[i] = (OPJ_UINT8)getc(IN);
                                lut_G[i] = (OPJ_UINT8)getc(IN);
                                lut_R[i] = (OPJ_UINT8)getc(IN);
                                (void)getc(IN); /* padding */
                                has_color |= (lut_B[i] ^ lut_G[i]) | (lut_G[i] ^ lut_R[i]);
                            }
                            if (has_color) {
                                numcmpts = 3U;
                            }
                        }
                    } else {
                        numcmpts = 3U;
                        if ((Info_h.biCompression == 3) && (Info_h.biAlphaMask != 0U)) {
                            numcmpts++;
                        }
                    }

                    if (Info_h.biWidth == 0 || Info_h.biHeight == 0) {

                    if (Info_h.biBitCount > (((OPJ_UINT32) - 1) - 31) / Info_h.biWidth) {
                    stride = ((Info_h.biWidth * Info_h.biBitCount + 31U) / 32U) *
                            4U; /* rows are aligned on 32bits */
                    if (Info_h.biBitCount == 4 &&
                            Info_h.biCompression == 2) { /* RLE 4 gets decoded as 8 bits data for now... */
                        if (8 > (((OPJ_UINT32) - 1) - 31) / Info_h.biWidth) {
                        stride = ((Info_h.biWidth * 8U + 31U) / 32U) * 4U;
                    }

                    if (stride > ((OPJ_UINT32) - 1) / sizeof(OPJ_UINT8) / Info_h.biHeight) {
                    pData = (OPJ_UINT8 *) calloc(1, sizeof(OPJ_UINT8) * stride * Info_h.biHeight);
                    if (pData == NULL) {
                    /* Place the cursor at the beginning of the image information */
                    fseek(IN, 0, SEEK_SET);
                    fseek(IN, (long)File_h.bfOffBits, SEEK_SET);

                    switch (Info_h.biCompression) {
                    case 0:
                    case 3:
                        /* read raw data */
                        l_result = bmp_read_raw_data(IN, pData, stride, Info_h.biWidth,
                                                    Info_h.biHeight);
                        break;
                    case 1:
                        /* read rle8 data */
                        l_result = bmp_read_rle8_data(IN, pData, stride, Info_h.biWidth,
                                                    Info_h.biHeight);
            if (!image) {
            break;

#ifdef OPJ_HAVE_LIBTIFF
        case TIF_DFMT:
            image = tiftoimage(parameters.infile, &parameters);
            if (!image) {
            break;
#endif /* OPJ_HAVE_LIBTIFF */

        case RAW_DFMT:
            image = rawtoimage(parameters.infile, &parameters, &raw_cp);
            if (!image) {
            break;

        case RAWL_DFMT:
            image = rawltoimage(parameters.infile, &parameters, &raw_cp);
            if (!image) {
            break;

        case TGA_DFMT:
            image = tgatoimage(parameters.infile, &parameters);
            if (!image) {
            break;

#ifdef OPJ_HAVE_LIBPNG
        case PNG_DFMT:
            image = pngtoimage(parameters.infile, &parameters);
            if (!image) {
            break;
#endif /* OPJ_HAVE_LIBPNG */
        }

        /* Can happen if input file is TIFF or PNG
        * and OPJ_HAVE_LIBTIF or OPJ_HAVE_LIBPNG is undefined
        */
        if (!image) {

        /* Decide if MCT should be used */
        if (parameters.tcp_mct == (char)
                255) { /* mct mode has not been set in commandline */
            parameters.tcp_mct = (image->numcomps >= 3) ? 1 : 0;
        } else {            /* mct mode has been set in commandline */
            if ((parameters.tcp_mct == 1) && (image->numcomps < 3)) {
            if ((parameters.tcp_mct == 2) && (!parameters.mct_data)) {
        }

        /* encode the destination image */
        /* ---------------------------- */

        switch (parameters.cod_format) {
        case J2K_CFMT: { /* JPEG-2000 codestream */
            /* Get a decoder handle */
            l_codec = opj_create_compress(OPJ_CODEC_J2K);
            break;
        }

        /* catch events using our callbacks and give a local context */
        opj_set_info_handler(l_codec, info_callback, 00);
        opj_set_warning_handler(l_codec, warning_callback, 00);
        opj_set_error_handler(l_codec, error_callback, 00);

        if (bUseTiles) {
            parameters.cp_tx0 = 0;
            parameters.cp_ty0 = 0;
            parameters.tile_size_on = OPJ_TRUE;
            parameters.cp_tdx = 512;
            parameters.cp_tdy = 512;
        }
        if (! opj_setup_encoder(l_codec, &parameters, image)) {

        /* open a byte stream for writing and allocate memory for all tiles */
        l_stream = opj_stream_create_default_file_stream(parameters.outfile, OPJ_FALSE);
        if (! l_stream) {

        /* encode the image */
        bSuccess = opj_start_compress(l_codec, image, l_stream);
        if (!bSuccess)  {
            fprintf(stderr, "failed to encode image: opj_start_compress\n");
        }
        if (bSuccess && bUseTiles) {
        } else {
            bSuccess = bSuccess && opj_encode(l_codec, l_stream);

/* src/lib/openjp2/openjpeg.c:819 */
OPJ_BOOL OPJ_CALLCONV opj_encode(opj_codec_t *p_info, opj_stream_t *p_stream)
{
    if (p_info && p_stream) {
        opj_codec_private_t * l_codec = (opj_codec_private_t *) p_info;
        opj_stream_private_t * l_stream = (opj_stream_private_t *) p_stream;

        if (! l_codec->is_decompressor) {
            return l_codec->m_codec_data.m_compression.opj_encode(l_codec->m_codec,
                    l_stream,
                    &(l_codec->m_event_mgr));

/* src/lib/openjp2/openjpeg.c:629 */
opj_codec_t* OPJ_CALLCONV opj_create_compress(OPJ_CODEC_FORMAT p_format)
{
    opj_codec_private_t *l_codec = 00;

    l_codec = (opj_codec_private_t*)opj_calloc(1, sizeof(opj_codec_private_t));
    if (!l_codec) {
        return 00;
    }

    l_codec->is_decompressor = 0;

    switch (p_format) {
    case OPJ_CODEC_J2K:
        l_codec->m_codec_data.m_compression.opj_encode = (OPJ_BOOL(*)(void *,
                struct opj_stream_private *,
                struct opj_event_mgr *)) opj_j2k_encode;

/* src/lib/openjp2/j2k.c:11279 */
OPJ_BOOL opj_j2k_encode(opj_j2k_t * p_j2k,
                        opj_stream_private_t *p_stream,
                        opj_event_mgr_t * p_manager)
{
    OPJ_UINT32 i, j;
    OPJ_UINT32 l_nb_tiles;
    OPJ_SIZE_T l_max_tile_size = 0, l_current_tile_size;
    OPJ_BYTE * l_current_data = 00;
    OPJ_BOOL l_reuse_data = OPJ_FALSE;
    opj_tcd_t* p_tcd = 00;

    /* preconditions */
    assert(p_j2k != 00);
    assert(p_stream != 00);
    assert(p_manager != 00);

    p_tcd = p_j2k->m_tcd;

    l_nb_tiles = p_j2k->m_cp.th * p_j2k->m_cp.tw;
    if (l_nb_tiles == 1) {
        l_reuse_data = OPJ_TRUE;
#ifdef __SSE__
        for (j = 0; j < p_j2k->m_tcd->image->numcomps; ++j) {
            opj_image_comp_t * l_img_comp = p_tcd->image->comps + j;
            if (((size_t)l_img_comp->data & 0xFU) !=
                    0U) { /* tile data shall be aligned on 16 bytes */
                l_reuse_data = OPJ_FALSE;
            }
        }
#endif
    }
    for (i = 0; i < l_nb_tiles; ++i) {
        if (! opj_j2k_pre_write_tile(p_j2k, i, p_stream, p_manager)) {
            if (l_current_data) {
                opj_free(l_current_data);
            }
            return OPJ_FALSE;
        }

        /* if we only have one tile, then simply set tile component data equal to image component data */
        /* otherwise, allocate the data */
        for (j = 0; j < p_j2k->m_tcd->image->numcomps; ++j) {
            opj_tcd_tilecomp_t* l_tilec = p_tcd->tcd_image->tiles->comps + j;
            if (l_reuse_data) {
                opj_image_comp_t * l_img_comp = p_tcd->image->comps + j;
                l_tilec->data  =  l_img_comp->data;
                l_tilec->ownsData = OPJ_FALSE;
            } else {
                ...
        }
        l_current_tile_size = opj_tcd_get_encoded_tile_size(p_j2k->m_tcd);
        if (!l_reuse_data) {
            if (l_current_tile_size > l_max_tile_size) {
                OPJ_BYTE *l_new_current_data = (OPJ_BYTE *) opj_realloc(l_current_data,
                                               l_current_tile_size);
                if (! l_new_current_data) {
                    if (l_current_data) {
                        opj_free(l_current_data);
                    }
                    opj_event_msg(p_manager, EVT_ERROR, "Not enough memory to encode all tiles\n");
                    return OPJ_FALSE;
                }
                l_current_data = l_new_current_data;
                l_max_tile_size = l_current_tile_size;
            }
            if (l_current_data == NULL) {
                /* Should not happen in practice, but will avoid Coverity to */
                /* complain about a null pointer dereference */
                assert(0);
                return OPJ_FALSE;
            }

            /* copy image data (32 bit) to l_current_data as contiguous, all-component, zero offset buffer */
            /* 32 bit components @ 8 bit precision get converted to 8 bit */
            /* 32 bit components @ 16 bit precision get converted to 16 bit */
            opj_j2k_get_tile_data(p_j2k->m_tcd, l_current_data);

            /* now copy this data into the tile component */
            if (! opj_tcd_copy_tile_data(p_j2k->m_tcd, l_current_data,
                                         l_current_tile_size)) {
				...
        }

        if (! opj_j2k_post_write_tile(p_j2k, ...)) { // p_j2k->m_tcd->tcd_image->tiles

/* src/lib/openjp2/j2k.c:11531 */
static OPJ_BOOL opj_j2k_post_write_tile(opj_j2k_t * p_j2k, ...)
{
    ...
    if (! opj_j2k_write_first_tile_part(p_j2k, ...)) {

/* src/lib/openjp2/j2k.c:11773 */
static OPJ_BOOL opj_j2k_write_first_tile_part(opj_j2k_t *p_j2k, ...)
{
    ...

    opj_tcd_t * l_tcd = 00;
    ...

    l_tcd = p_j2k->m_tcd;
    ...

    l_tcd->cur_pino = 0;

    ...
    if (! opj_j2k_write_sod(p_j2k, l_tcd, ...)) {

/* src/lib/openjp2/j2k.c:4691 */
static OPJ_BOOL opj_j2k_write_sod(opj_j2k_t *p_j2k, opj_tcd_t * p_tile_coder, ...)
{
	...

    if (! opj_tcd_encode_tile(p_tile_coder, ...))

/* src/lib/openjp2/tcd.c:1414 */
OPJ_BOOL opj_tcd_encode_tile(opj_tcd_t *p_tcd, ...)
{

    if (p_tcd->cur_tp_num == 0) {
		...
        /* FIXME  _ProfStart(PGROUP_T1); */
        if (! opj_tcd_t1_encode(p_tcd)) {

/* src/lib/openjp2/tcd.c:2511 */
static OPJ_BOOL opj_tcd_t1_encode(opj_tcd_t *p_tcd)
{
    ...

    if (! opj_t1_encode_cblks(l_t1, p_tcd->tcd_image->tiles, l_tcp, l_mct_norms, 
                              l_mct_numcomps)) {

/* src/lib/openjp2/t1.c:2137 */
OPJ_BOOL opj_t1_encode_cblks(opj_t1_t *t1, opj_tcd_tile_t *tile, ...)
{
    ...

    for (compno = 0; compno < tile->numcomps; ++compno) {
        opj_tcd_tilecomp_t* tilec = &tile->comps[compno];
        ...

        for (resno = 0; resno < tilec->numresolutions; ++resno) {
            opj_tcd_resolution_t *res = &tilec->resolutions[resno];

            for (bandno = 0; bandno < res->numbands; ++bandno) {
                opj_tcd_band_t* OPJ_RESTRICT band = &res->bands[bandno];
                ...
                for (precno = 0; precno < res->pw * res->ph; ++precno) {
                    opj_tcd_precinct_t *prc = &band->precincts[precno];

                    for (cblkno = 0; cblkno < prc->cw * prc->ch; ++cblkno) {
```
</details>

## CWE-78: OS Command Injection
### CVE-2017-15108
가상 머신 게스트 에이전트인 `spice-vdagent`에서, 파일 전송 완료 후 저장 디렉터리를 여는 과정 중 전달받은 경로를 검증하지 않고 쉘 명령으로 만들어 실행하여, 공격자가 임의의 명령을 주입할 수 있는 ****OS Command Injection 취약점****

1.  SPICE 프로토콜을 통해 `spice-vdagent`가 파일 전송 데이터 메시지(`VDAGENTD_FILE_XFER_DATA`)를 수신하고, 이를 처리하기 위해 `daemon_read_complete` 콜백 함수가 호출됩니다.

2.  `daemon_read_complete` 함수는 전달받은 메시지를 `vdagent_file_xfers_data` 함수로 넘겨 파일 쓰기 작업을 수행합니다.

3.  `vdagent_file_xfers_data` 함수 내에서 파일 쓰기가 완료되면, 전송이 모두 끝났는지 확인하는 조건문(`task->read_bytes >= task->file_size`)에 진입합니다.

4.  **(버그 발생)** 모든 파일 전송이 완료된 경우, 저장된 디렉터리를 열어주기 위해 `snprintf`를 사용하여 `xdg-open '%s'&` 형태의 쉘 명령 문자열을 생성합니다. 이 과정에서 경로를 담고 있는 `xfers->save_dir` 변수의 내용을 검증하거나 이스케이프하지 않고 그대로 문자열에 삽입합니다.

5.  공격자에 의해 조작된 `save_dir` 경로가 포함된 명령 문자열이 `system()` 함수(Sink)에 그대로 전달되어 실행됩니다. 이로 인해 공격자는 `'; id; #`와 같은 페이로드를 `save_dir`에 담아 원하는 임의의 명령을 실행할 수 있습니다.

이 CVE 취약점을 유발하는 코드(sink:src/vdagent/file-xfers.c:341)는 아래와 같다.

```c
void vdagent_file_xfers_data(struct vdagent_file_xfers *xfers,
    VDAgentFileXferDataMessage *msg)
{
    AgentFileXferTask *task;
    int len, status = -1;

    g_return_if_fail(xfers != NULL);

    task = vdagent_file_xfers_get_task(xfers, msg->id);
    if (!task)
        return;

    len = write(task->file_fd, msg->data, msg->size);
    if (len == msg->size) {
        task->read_bytes += msg->size;
        if (task->read_bytes >= task->file_size) {
            if (task->read_bytes == task->file_size) {
                if (xfers->debug)
                    syslog(LOG_DEBUG, "file-xfer: task %u %s has completed",
                           task->id, task->file_name);
                close(task->file_fd);
                task->file_fd = -1;
                if (xfers->open_save_dir &&
                        task->file_xfer_nr == task->file_xfer_total &&
                        g_hash_table_size(xfers->xfers) == 1) {
                    char buf[PATH_MAX];
                    snprintf(buf, PATH_MAX, "xdg-open '%s'&", xfers->save_dir);
                    status = system(buf);
```

<details>
<summary>이 코드의 취약점을 표현하는 슬라이스</summary>

```c
/* src/vdagent/vdagent.c:354 */
static gboolean vdagent_init_async_cb(gpointer user_data)
{
    VDAgent *agent = user_data;
    GError *err = NULL;

    agent->conn = udscs_connect(
        vdagentd_socket,
        daemon_read_complete,
        daemon_error_cb,
        debug,
        &err
    );
}

/* src/vdagent/vdagent.c:222 */
static void daemon_read_complete(UdscsConnection *conn,
    struct udscs_message_header *header, uint8_t *data)
{
    VDAgent *agent = g_object_get_data(G_OBJECT(conn), "agent");

    switch (header->type) {
        case VDAGENTD_FILE_XFER_DATA:
            if (agent->xfers != NULL) {
                vdagent_file_xfers_data(
                    agent->xfers,
                    (VDAgentFileXferDataMessage *)data
                );
            }
            break;
        default:
            break;
    }
}
/* src/vdagent/file-xfers.c:341 */
void vdagent_file_xfers_data(struct vdagent_file_xfers *xfers,
    VDAgentFileXferDataMessage *msg)
{
    AgentFileXferTask *task;
    int len, status = -1;

    task = vdagent_file_xfers_get_task(xfers, msg->id);
    len = write(task->file_fd, msg->data, msg->size);

    if (len == msg->size) {
        task->read_bytes += msg->size;

        if (task->read_bytes >= task->file_size) {
            if (task->read_bytes == task->file_size) {
                if (xfers->debug) {
                    syslog(
                        LOG_DEBUG,
                        "file-xfer: task %u %s has completed",
                        task->id,
                        task->file_name
                    );
                }

                close(task->file_fd);
                task->file_fd = -1;

                if (xfers->open_save_dir &&
                    task->file_xfer_nr == task->file_xfer_total &&
                    g_hash_table_size(xfers->xfers) == 1) {
                    char buf[PATH_MAX];
                    snprintf(buf, PATH_MAX, "xdg-open '%s'&", xfers->save_dir);
                    status = system(buf);
                }
            }
        }
    }
}
```
</details>

### CVE-2017-15924
Shadowsocks-libev의 `ss-manager`에서, UDP를 통해 수신한 서버 추가 요청을 부적절하게 처리하여, 공격자가 쉘 메타문자를 주입해 임의의 명령을 실행할 수 있는 **OS Command Injection 취약점**

1.  `ss-manager` 프로세스는 관리 명령을 수신하기 위해 UDP 소켓을 열고, 데이터 수신 시 `manager_recv_cb` 콜백 함수를 호출하도록 설정합니다.

2.  공격자는 서버를 추가(`"action": "add"`)하는 악의적인 JSON 요청을 UDP 소켓으로 전송합니다. `manager_recv_cb` 함수는 이 요청을 받아 `get_server()`를 통해 JSON을 파싱하고, 검증되지 않은 `method`, `port` 등의 값을 `server` 구조체에 저장합니다.

3.  `manager_recv_cb`는 악성 데이터가 담긴 `server` 구조체를 `add_server` 함수에 전달하고, 이어서 `construct_command_line` 함수가 호출됩니다.

4.  **(버그 발생)** `construct_command_line` 함수는 새로운 `shadowsocks` 서버를 실행하기 위한 쉘 명령 문자열을 `snprintf`로 생성합니다. 이 과정에서 `server->method`, `server->port` 등 외부로부터 받은 값을 **아무런 검증이나 이스케이프 처리 없이** `%s` 포맷 지정자를 통해 그대로 문자열에 삽입합니다.

5.  공격자에 의해 `'; id; #`와 같은 쉘 메타문자가 포함된 `method` 값이 그대로 명령 문자열의 일부가 되고, 이 최종 명령 문자열이 `add_server` 함수 내의 `system()`(Sink)으로 전달되어 실행됩니다. 결과적으로 공격자가 의도한 임의의 명령이 시스템에서 실행됩니다.

이 CVE 취약점을 유발하는 코드(sink:src/lib/openjp2/t1.c:2137)는 아래와 같다.

```c
static int
add_server(struct manager_ctx *manager, struct server *server)
{
    int ret = check_port(manager, server);
    ...
    cork_hash_table_put(server_table, (void *)server->port, (void *)server, &new, NULL, NULL);
    char *cmd = construct_command_line(manager, server);
    if (system(cmd) == -1) {
```

<details>
<summary>이 코드의 취약점을 표현하는 슬라이스</summary>

```c
/* src/manager.c:1187 */
int main(int argc, char **argv)
{
    int sfd;
    if (ip_addr.host == NULL || ip_addr.port == NULL) {
        struct sockaddr_un svaddr;
        sfd = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (sfd == -1) {
            return -1;
        }
        setnonblocking(sfd);
        if (bind(sfd, (struct sockaddr *)&svaddr, sizeof(struct sockaddr_un)) == -1) {
            return -1;
        }
    }
    manager.fd = sfd;
    ev_io_init(&manager.io, manager_recv_cb, manager.fd, EV_READ);
}
/* src/manager.c:609 */
static void manager_recv_cb(EV_P_ ev_io *w, int revents)
{
    struct manager_ctx *manager = (struct manager_ctx *)w;
    int r = recvfrom(manager->fd, buf, BUF_SIZE, 0, (struct sockaddr *)&claddr, &len);
    if (r == -1) {
        return;
    }
    if (r > BUF_SIZE / 2) {
        return;
    }
    char *action = get_action(buf, r);
    if (action == NULL) {
        return;
    }
    if (strcmp(action, "add") == 0) {
        struct server *server = get_server(buf, r);
        if (server == NULL || server->port[0] == 0 || server->password[0] == 0) {
            return;
        }
        int ret = add_server(manager, server);
        if (ret == -1) {
            return;
        }
    }
}

/* src/manager.c:486 */
static int add_server(struct manager_ctx *manager, struct server *server)
{
    int ret = check_port(manager, server);
    if (ret == -1) {
        return -1;
    }
    cork_hash_table_put(server_table, (void *)server->port, (void *)server, &new, NULL, NULL);
    char *cmd = construct_command_line(manager, server);
        /* src/manager.c:134 */
        static char *construct_command_line(struct manager_ctx *manager, struct server *server) {
            static char cmd[BUF_SIZE];
            char *method = manager->method;

            build_config(working_dir, server);

            if (server->method) {
                method = server->method;
            }
            memset(cmd, 0, BUF_SIZE);
            snprintf(cmd, BUF_SIZE,
                    "%s -m %s --manager-address %s -f %s/.shadowsocks_%s.pid -c %s/.shadowsocks_%s.conf",
                    executable, method, manager->manager_address,
                    working_dir, server->port, working_dir, server->port);
            return cmd;
        }
    if (cmd == NULL) {
        return -1;
    }
    if (system(cmd) == -1) {
        ERROR("add_server_system");
        return -1;
    }
    return 0;
}
```
</details>

### CVE-2018-6791
KDE Plasma Workspace의 장치 관리 기능에서, `.desktop` 파일에 정의된 실행 명령의 매크로를 확장할 때 USB 드라이브의 볼륨 레이블과 같은 외부 값을 검증하지 않아, 조작된 장치를 연결 시 임의의 명령이 실행되는 **OS Command Injection 취약점**

1.  공격자가 악의적인 쉘 메타문자가 포함된 볼륨 레이블(예: `MyUSB';id;'`)을 가진 USB 드라이브와, 해당 장치에 대한 특정 작업(Action)이 정의된 `.desktop` 파일을 준비합니다.

2.  사용자가 해당 장치를 시스템에 연결하면, KDE의 `SolidUiServer`는 `.desktop` 파일을 읽어 `Exec=` 필드에 정의된 명령어 템플릿(예: `some-command --mount %f`)을 `KServiceAction` 객체에 저장합니다.

3.  사용자가 장치 알림 등에서 해당 작업을 실행하면, `DeviceServiceAction::execute` 메소드가 호출되어 명령어 템플릿이 담긴 `KServiceAction` 객체를 `DelayedExecutor`에 전달합니다.

4.  **(버그 발생)** `DelayedExecutor::delayedExecute` 함수는 저장된 명령어 템플릿을 가져와 `MacroExpander`를 통해 매크로(예: `%f`)를 실제 장치 값(볼륨 레이블 등)으로 확장합니다. 이 과정에서 악의적인 볼륨 레이블이 **아무런 검증이나 이스케이프 처리 없이** 명령어 문자열에 그대로 삽입됩니다.

5.  쉘 메타문자가 포함된 최종 명령어 문자열(예: `some-command --mount 'MyUSB';id;''`)이 `KRun::runCommand()` 함수(Sink)에 전달되어 실행됩니다. 이로 인해 공격자가 볼륨 레이블에 심어놓은 임의의 명령(`id`)이 시스템에서 실행됩니다. 

이 CVE 취약점을 유발하는 코드(sink:soliduiserver/deviceserviceaction.cpp:163)는 아래와 같다.

```c
void DelayedExecutor::delayedExecute(const QString &udi)
{
    Solid::Device device(udi);

    QString exec = m_service.exec();
    MacroExpander mx(device);
    mx.expandMacros(exec);

    KRun::runCommand(exec, QString(), m_service.icon(), 0);
```

<details>
<summary>이 코드의 취약점을 표현하는 슬라이스</summary>

```c
/* userDefinedServices는 KDesktopFileActions의 메소드인데 이는 외부 라이브러리에 있는 클래스이고, 파일에서 불러오는 것! 

`random.desktop` 파일 예시 // 새로운 장치(예: USB 드라이브)가 연결되었을 때, 해당 장치에 대해 사용자가 수행할 수 있는 작업 목록
[Desktop Entry]
Name=MyPlayer
Exec=myplayer %U
Icon=myplayer
Type=Application
Actions=Play,Edit

[Desktop Action Play]
Name=Play
Exec=myplayer --play %U
Icon=media-playback-start

[Desktop Action Edit]
Name=Edit
Exec=myplayer --edit %U
Icon=document-edit

위 파일에서 Exec 값이 m_service.exec() 값으로 반환되는 것으로 보인다.

*/
/* soliduiserver/soliduiserver.cpp:77 */
void SolidUiServer::showActionsDialog(const QString &udi,
                                      const QStringList &desktopFiles)
{
    if (m_udiToActionsDialog.contains(udi)) {
    QList<DeviceAction*> actions;
    foreach (const QString &desktop, desktopFiles) {
        const QString filePath = QStandardPaths::locate(QStandardPaths::GenericDataLocation, "solid/actions/"+desktop);

        QList<KServiceAction> services = KDesktopFileActions::userDefinedServices(filePath, true);

        foreach (const KServiceAction &service, services) {
            DeviceServiceAction *action = new DeviceServiceAction();
            action->setService(service);
            actions << action;
        }
    }

    // Only one action, execute directly
    if (actions.size()==1) {
        DeviceAction *action = actions.takeFirst();
        Solid::Device device(udi);
        action->execute(device);


/* soliduiserver/deviceserviceaction.cpp:95 */
void DeviceServiceAction::setService(const KServiceAction& service)
{
    DeviceAction::setIconName(service.icon());
    DeviceAction::setLabel(service.text());

    m_service = service;

/* soliduiserver/deviceserviceaction.h:80 */
class DeviceServiceAction : public DeviceAction
{
public:
    DeviceServiceAction();
    QString id() const override;
    void execute(Solid::Device &device) override;

    void setService(const KServiceAction& service);
    KServiceAction service() const;

private:
    KServiceAction m_service;
};

/* soliduiserver/deviceserviceaction.cpp:77 */
void DeviceServiceAction::execute(Solid::Device &device)
{
    new DelayedExecutor(m_service, device);

/* soliduiserver/deviceserviceaction.cpp:139 */
DelayedExecutor::DelayedExecutor(const KServiceAction &service, Solid::Device &device): m_service(service)

/* soliduiserver/deviceserviceaction.cpp:163 */
void DelayedExecutor::delayedExecute(const QString &udi)
{
    Solid::Device device(udi);

    QString exec = m_service.exec();
    MacroExpander mx(device);
    mx.expandMacros(exec);

    KRun::runCommand(exec, QString(), m_service.icon(), 0);
```
</details>

### CVE-2018-16863
Ghostscript의 `-dSAFER` 샌드박스 모드에서, 실패한 `restore` 연산 처리의 결함으로 파일 접근 제어가 무력화된 후, `%pipe%` 장치를 통해 파일 출력 경로를 조작하여 임의의 명령을 실행할 수 있는 OS Command Injection 취약점

1.  Ghostscript가 파일 시스템 접근 및 명령어 실행을 차단하는 보안 샌드박스 모드(`-dSAFER`)로 실행됩니다.

2.  공격자는 먼저 PostScript의 오류 처리 메커니즘을 악용합니다. `restore` 연산을 의도적으로 실패시킨 후 오류를 `stopped`로 잡아내면, `-dSAFER`에 의해 설정된 파일 접근 제한이 해제되는 **논리적 결함(sandbox escape)이 발생**합니다.

3.  샌드박스가 무력화된 상태에서, 공격자는 출력 파일 경로(`OutputFile`)를 `%pipe%` 장치를 사용하도록 설정하고, 파이프를 통해 실행할 명령어(예: `id`)를 파일명 부분에 포함시킵니다. (예: `%pipe%id`)

4.  `showpage` 등의 명령으로 출력 작업이 트리거되면, Ghostscript 내부에서는 이 경로를 처리하기 위해 `gs_findiodevice`를 통해 `%pipe%` 핸들러를 찾고, **함수 포인터를 통해 `pipe_fopen` 함수를 호출**하며, 파일명 부분(`id`)을 인자로 전달합니다.

5.  최종적으로 `pipe_fopen` 함수는 전달받은 `id` 문자열을 `popen()` 함수(Sink)에 인자로 넘겨 실행하여, 공격자가 의도한 임의의 명령이 시스템에서 실행됩니다.

이 CVE 취약점을 유발하는 코드(sink:base/gdevpipe.c:60)는 아래와 같다.

```c
/* Sink: pipe_fopen */
/* function pointer 들을 필드로 갖고 있는 strcuture를 joern에서 잘 처리하는지 확인 필요 */ 

static int
pipe_fopen(gx_io_device * iodev, const char *fname, const char *access,
           FILE ** pfile, char *rfname, uint rnamelen)
{
#ifdef GS_NO_FILESYSTEM
    return 0;
#else
    errno = 0;
    /*
     * Some platforms allow opening a pipe with a '+' in the access
     * mode, even though pipes are not positionable.  Detect this here.
     */
    if (strchr(access, '+'))
        return_error(gs_error_invalidfileaccess);
    /*
     * The OSF/1 1.3 library doesn't include const in the
     * prototype for popen, so we have to break const here.
     */
    *pfile = popen((char *)fname, (char *)access);
```

<details>
<summary>이 코드의 취약점을 표현하는 슬라이스</summary>

```c
/*
link: https://bugs.ghostscript.com/show_bug.cgi?id=699654
/invalidaccess checks stop working after a failed restore, so you can just execute shell commands if you handle the error. Exploitation is very trivial. Repro:

$ gs -q -sDEVICE=ppmraw -dSAFER -sOutputFile=/dev/null 
GS>legal
GS>{ null restore } stopped { pop } if
GS>legal
GS>mark /OutputFile (%pipe%id) currentdevice putdeviceprops
GS<1>showpage
uid=1000(taviso) gid=1000(taviso) groups=1000(taviso),10(wheel) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

const gx_io_device gs_iodev_pipe = {
    "%pipe%", "Special",
    {iodev_no_init, iodev_no_finit, iodev_no_open_device,
     NULL , pipe_fopen, pipe_fclose,
     iodev_no_delete_file, iodev_no_rename_file, iodev_no_file_status,
     iodev_no_enumerate_files, NULL, NULL,
     iodev_no_get_params, iodev_no_put_params
    }
};
*/

/* Source: gx_device_open_output_file */
/* base/gsdevice.c:1193 */
int
gx_device_open_output_file(const gx_device * dev, char *fname,
                           bool binary, bool positionable, FILE ** pfile)
{
    gs_parsed_file_name_t parsed;
    const char *fmt;
    char *pfname = (char *)gs_alloc_bytes(dev->memory, gp_file_name_sizeof, "gx_device_open_output_file(pfname)");
    int code;

    if (pfname == NULL) {
        code = gs_note_error(gs_error_VMerror);
	goto done;
     }

    if (strlen(fname) == 0) {
        code = gs_note_error(gs_error_undefinedfilename);
        emprintf1(dev->memory, "Device '%s' requires an output file but no file was specified.\n", dev->dname);
        goto done;
    }
    code = gx_parse_output_file_name(&parsed, &fmt, fname, strlen(fname), dev->memory);

/* base/gsdevice.c:1094 */
int
gx_parse_output_file_name(gs_parsed_file_name_t *pfn, const char **pfmt,
                          const char *fname, uint fnlen, gs_memory_t *memory)
{
    int code;

    *pfmt = 0;
    pfn->memory = 0;
    pfn->iodev = NULL;
    pfn->fname = NULL;		/* irrelevant since length = 0 */
    pfn->len = 0;
    if (fnlen == 0)  		/* allow null name */
        return 0;
    /*
     * If the file name begins with a %, it might be either an IODevice
     * or a %nnd format.  Check (carefully) for this case.
     */
    code = gs_parse_file_name(pfn, fname, fnlen, memory);
    if (code < 0) {
        if (fname[0] == '%') {
            /* not a recognized iodev -- may be a leading format descriptor */
            pfn->len = fnlen;
            pfn->fname = fname;
            code = gx_parse_output_format(pfn, pfmt);
        }
        if (code < 0)
            return code;
    }
    if (!pfn->iodev) {
        if ( (pfn->len == 1) && (pfn->fname[0] == '-') ) {
            pfn->iodev = gs_findiodevice(memory, (const byte *)"%stdout", 7);
            pfn->fname = NULL;
        } else if (pfn->fname[0] == '|') {
            pfn->iodev = gs_findiodevice(memory, (const byte *)"%pipe", 5);

/* base/gsdevice.c:1237 */
/* Open the output file for a device. */
int
gx_device_open_output_file(const gx_device * dev, char *fname,
                           bool binary, bool positionable, FILE ** pfile)
{
    gs_parsed_file_name_t parsed;
    const char *fmt;
    char *pfname = (char *)gs_alloc_bytes(dev->memory, gp_file_name_sizeof, "gx_device_open_output_file(pfname)");
    int code;

    if (pfname == NULL) {
        code = gs_note_error(gs_error_VMerror);
	goto done;
     }

    if (strlen(fname) == 0) {
        code = gs_note_error(gs_error_undefinedfilename);
        emprintf1(dev->memory, "Device '%s' requires an output file but no file was specified.\n", dev->dname);
        goto done;
    }
    code = gx_parse_output_file_name(&parsed, &fmt, fname, strlen(fname), dev->memory);
    if (code < 0) {
        goto done;
    }

    if (parsed.iodev && !strcmp(parsed.iodev->dname, "%stdout%")) {
        if (parsed.fname) {
            code = gs_note_error(gs_error_undefinedfilename);
	    goto done;
	}
        *pfile = dev->memory->gs_lib_ctx->fstdout;
        /* Force stdout to binary. */
        code = gp_setmode_binary(*pfile, true);
	goto done;
    } else if (parsed.iodev && !strcmp(parsed.iodev->dname, "%pipe%")) {
        positionable = false;
    }
    if (fmt) {						/* filename includes "%nnd" */
        long count1 = dev->PageCount + 1;

        while (*fmt != 'l' && *fmt != '%')
            --fmt;
        if (*fmt == 'l')
            gs_sprintf(pfname, parsed.fname, count1);
        else
            gs_sprintf(pfname, parsed.fname, (int)count1);
    } else if (parsed.len && strchr(parsed.fname, '%'))	/* filename with "%%" but no "%nnd" */
        gs_sprintf(pfname, parsed.fname);
    else
        pfname[0] = 0; /* 0 to use "fname", not "pfname" */
    if (pfname[0]) {
        parsed.fname = pfname;
        parsed.len = strlen(parsed.fname);
    }
    if (positionable || (parsed.iodev && parsed.iodev != iodev_default(dev->memory))) {
        char fmode[4];

        if (!parsed.fname) {
            code = gs_note_error(gs_error_undefinedfilename);
	    goto done;
	}
        strcpy(fmode, gp_fmode_wb);
        if (positionable)
            strcat(fmode, "+");
        code = parsed.iodev->procs.gp_fopen(parsed.iodev, parsed.fname, fmode,
                                         pfile, NULL, 0); // gdevpipe.c에 pipe_fopen()을 호출

/* str이 OutputFile인거고 gx_io_device *iodev = libctx->io_device_table[i]; 에서 적절한 device를 찾은 다음에
if (dname && strlen(dname) == len + 1 && !memcmp(str, dname, len))에서 device의 첫번째 인자 "%PIPE%"와 str 값을 비교 */
/* base/gsiodev.c:378 */
/* Look up an IODevice name. */
/* The name may be either %device or %device%. */
gx_io_device *
gs_findiodevice(const gs_memory_t *mem, const byte * str, uint len) 
{
    int i;
    gs_lib_ctx_t *libctx = gs_lib_ctx_get_interp_instance(mem);

    if (libctx->io_device_table == 0)
    	return 0;
    if (len > 1 && str[len - 1] == '%')
        len--;
    for (i = 0; i < libctx->io_device_table_count; ++i) {
        gx_io_device *iodev = libctx->io_device_table[i];
        const char *dname = iodev->dname;

        if (dname && strlen(dname) == len + 1 && !memcmp(str, dname, len))
            return iodev;
    }
    return 0;
}

/* base/gdevpipe.c:33 */
const gx_io_device gs_iodev_pipe = {
    "%pipe%", "Special",
    {iodev_no_init, iodev_no_finit, iodev_no_open_device,
     NULL /*iodev_os_open_file */ , pipe_fopen, pipe_fclose,
     iodev_no_delete_file, iodev_no_rename_file, iodev_no_file_status,
     iodev_no_enumerate_files, NULL, NULL,
     iodev_no_get_params, iodev_no_put_params
    }
};


/* Sink: pipe_fopen */
/* base/gdevpipe.c:60 */
/* function pointer 들을 필드로 갖고 있는 strcuture를 joern에서 잘 처리하는지 확인 필요 */ 

static int
pipe_fopen(gx_io_device * iodev, const char *fname, const char *access,
           FILE ** pfile, char *rfname, uint rnamelen)
{
#ifdef GS_NO_FILESYSTEM
    return 0;
#else
    errno = 0;
    /*
     * Some platforms allow opening a pipe with a '+' in the access
     * mode, even though pipes are not positionable.  Detect this here.
     */
    if (strchr(access, '+'))
        return_error(gs_error_invalidfileaccess);
    /*
     * The OSF/1 1.3 library doesn't include const in the
     * prototype for popen, so we have to break const here.
     */
    *pfile = popen((char *)fname, (char *)access);
```
</details>

### CVE-2019-13638~
GNU `patch` 유틸리티에서, ed 스크립트 형식의 패치를 처리할 때 출력 파일명(`-o` 옵션)을 검증 없이 쉘 명령의 일부로 사용하여, 조작된 파일명을 통해 임의의 명령을 실행할 수 있는 **OS Command Injection 취약점**

1.  공격자가 `patch` 유틸리티를 실행할 때, `-o` (또는 `--output`) 옵션을 사용하여 쉘 메타문자가 포함된 악의적인 출력 파일명(예: `';id;'`)을 인자로 전달합니다.

2.  `get_some_switches` 함수는 `-o` 옵션의 인자 값을 받아 전역 변수인 `outfile`에 저장하고, 이 값은 `main` 함수 루프 내의 `outname` 변수로 전달됩니다.

3.  `main` 함수는 `make_tempfile` 함수를 호출하면서 악성 `outname`을 전달하고, 이 값에 기반하여 생성된 임시 파일명이 또 다른 전역 변수인 `TMPOUTNAME`에 저장됩니다. 이 과정은 포인터를 통해 간접적으로 이뤄져 데이터 흐름 추적을 어렵게 합니다.

4.  **(버그 발생)** 패치 종류가 ed 스크립트 형식(`diff_type == ED_DIFF`)인 경우, `main` 함수는 오염된 전역 변수 `TMPOUTNAME`을 `do_ed_script` 함수의 `outname` 인자로 전달하여 호출합니다.

5.  `do_ed_script` 함수는 전달받은 `outname`을 아무런 검증 없이 `sprintf`를 통해 명령어 문자열(`buf`)의 일부로 만듭니다. 쉘 메타문자가 포함된 이 `buf`가 최종적으로 `execl` 함수(Sink)에 `sh -c`의 인자로 전달되어, 공격자가 주입한 임의의 명령이 실행됩니다.

이 CVE 취약점을 유발하는 코드(sink:src/pch.c:2473)는 아래와 같다.

```c
void
do_ed_script (char const *inname, char const *outname,
	      bool *outname_needs_removal, FILE *ofp)
{
    static char const editor_program[] = EDITOR_PROGRAM;
    ...
	sprintf (buf, "%s %s%s", editor_program,
		 verbosity == VERBOSE ? "" : "- ",
		 outname);
	fflush (stdout);

	pid = fork();
	if (pid == -1)
	else if (pid == 0)
	  {
	    dup2 (tmpfd, 0);
	    execl ("/bin/sh", "sh", "-c", buf, (char *) 0);
```

<details>
<summary>이 코드의 취약점을 표현하는 슬라이스</summary>

```c
/* 포인터 분석을 잘해야 함. make_tempfile()에서 TMPOUTNAME이 outname으로부터 업데이트 된 다는 사실을 interprocedure analysis로는 식별할 수 없다. */
/* src/patch.c:959 */
static void
get_some_switches (void)
{
    int optc;

    free (rejname);
    rejname = 0;
    if (optind == Argc)
	return;
    while ((optc = getopt_long (Argc, Argv, shortopts, longopts, (int *) 0))
	   != -1) {
	switch (optc) {
	    case 'o':
		outfile = xstrdup (optarg);

/* src/patch.c:253 */
int
main (int argc, char **argv)
{
    char const *val;
    bool somefailed = false;
    struct outstate outstate;
    struct stat tmpoutst;
    char numbuf[LINENUM_LENGTH_BOUND + 1];
    bool written_to_rejname = false;
    bool skip_reject_file = false;
    bool apply_empty_patch = false;
    mode_t file_type;
    int outfd = -1;
    bool have_git_diff = false;

    exit_failure = 2;
    set_program_name (argv[0]);
    init_time ();

    setbuf(stderr, serrbuf);

    bufsize = 8 * 1024;
    buf = xmalloc (bufsize);

    strippath = -1;

    val = getenv ("QUOTING_STYLE");
    {
      int i = val ? argmatch (val, quoting_style_args, 0, 0) : -1;
      set_quoting_style ((struct quoting_options *) 0,
			 i < 0 ? shell_quoting_style : (enum quoting_style) i);
    }

    posixly_correct = getenv ("POSIXLY_CORRECT") != 0;
    backup_if_mismatch = ! posixly_correct;
    patch_get = ((val = getenv ("PATCH_GET"))
		 ? numeric_string (val, true, "PATCH_GET value")
		 : 0);

    val = getenv ("SIMPLE_BACKUP_SUFFIX");
    simple_backup_suffix = val && *val ? val : ".orig";

    if ((version_control = getenv ("PATCH_VERSION_CONTROL")))
      version_control_context = "$PATCH_VERSION_CONTROL";
    else if ((version_control = getenv ("VERSION_CONTROL")))
      version_control_context = "$VERSION_CONTROL";

    init_backup_hash_table ();
    init_files_to_delete ();
    init_files_to_output ();

    /* parse switches */
    Argc = argc;
    Argv = argv;
    get_some_switches();

    /* Make get_date() assume that context diff headers use UTC. */
    if (set_utc)
      setenv ("TZ", "UTC", 1);

    if (make_backups | backup_if_mismatch)
      backup_type = get_version (version_control_context, version_control);

    init_output (&outstate);
    if (outfile)
      outstate.ofp = open_outfile (outfile);

    /* Make sure we clean up in case of disaster.  */
    set_signals (false);

    /* When the file to patch is specified on the command line, allow that file
       to lie outside the current working tree.  Still doesn't allow to follow
       symlinks.  */
    if (inname)
      unsafe = true;

    if (inname && outfile)
      {
	/* When an input and an output filename is given and the patch is
	   empty, copy the input file to the output file.  In this case, the
	   input file must be a regular file (i.e., symlinks cannot be copied
	   this way).  */
	apply_empty_patch = true;
	file_type = S_IFREG;
	inerrno = -1;
      }
    for (
	open_patch_file (patchname);
	there_is_another_patch (! (inname || posixly_correct), &file_type)
	  || apply_empty_patch;
	reinitialize_almost_everything(),
	  skip_reject_file = false,
	  apply_empty_patch = false
    ) {					/* for each patch in patch file */
      int hunk = 0;
      int failed = 0;
      bool mismatch = false;
      char const *outname = NULL;

      if (skip_rest_of_patch)
	somefailed = true;

      if (have_git_diff != pch_git_diff ())
	{
	  if (have_git_diff)
	    {
	      output_files (NULL);
	      inerrno = -1;
	    }
	  have_git_diff = ! have_git_diff;
	}

      if (TMPREJNAME_needs_removal)
	{
	  if (rejfp)
	    {
	      fclose (rejfp);
	      rejfp = NULL;
	    }
	  remove_if_needed (TMPREJNAME, &TMPREJNAME_needs_removal);
	}
      if (TMPOUTNAME_needs_removal)
        {
	  if (outfd != -1)
	    {
	      close (outfd);
	      outfd = -1;
	    }
	  remove_if_needed (TMPOUTNAME, &TMPOUTNAME_needs_removal);
	}

      if (! skip_rest_of_patch && ! file_type)
	{
	  say ("File %s: can't change file type from 0%o to 0%o.\n",
	       quotearg (inname),
	       (unsigned int) (pch_mode (reverse) & S_IFMT),
	       (unsigned int) (pch_mode (! reverse) & S_IFMT));
	  skip_rest_of_patch = true;
	  somefailed = true;
	}

      if (! skip_rest_of_patch)
	{
	  if (outfile)
	    outname = outfile;

/* src/util.c:1669 */
int
make_tempfile (char const **name, char letter, char const *real_name,
	       int flags, mode_t mode)
{
  char *template;
  struct try_safe_open_args args = {
    .flags = flags,
    .mode = mode,
  };
  int fd;

  if (real_name && ! dry_run)
    {
      char *dirname, *basename;

      dirname = dir_name (real_name);
      basename = base_name (real_name);

      template = xmalloc (strlen (dirname) + 1 + strlen (basename) + 9);
      sprintf (template, "%s/%s.%cXXXXXX", dirname, basename, letter);
      free (dirname);
      free (basename);
    }
  else
  fd = try_tempname(template, 0, &args, try_safe_open);
  *name = template;

/* src/patch.c:317 */
int
main (int argc, char **argv)
{
    char const *val;
    bool somefailed = false;
    struct outstate outstate;
    struct stat tmpoutst;
    char numbuf[LINENUM_LENGTH_BOUND + 1];
    bool written_to_rejname = false;
    bool skip_reject_file = false;
    bool apply_empty_patch = false;
    mode_t file_type;
    int outfd = -1;
    bool have_git_diff = false;

    exit_failure = 2;
    set_program_name (argv[0]);
    init_time ();

    setbuf(stderr, serrbuf);

    bufsize = 8 * 1024;
    buf = xmalloc (bufsize);

    strippath = -1;

    val = getenv ("QUOTING_STYLE");
    {
      int i = val ? argmatch (val, quoting_style_args, 0, 0) : -1;
      set_quoting_style ((struct quoting_options *) 0,
			 i < 0 ? shell_quoting_style : (enum quoting_style) i);
    }

    posixly_correct = getenv ("POSIXLY_CORRECT") != 0;
    backup_if_mismatch = ! posixly_correct;
    patch_get = ((val = getenv ("PATCH_GET"))
		 ? numeric_string (val, true, "PATCH_GET value")
		 : 0);

    val = getenv ("SIMPLE_BACKUP_SUFFIX");
    simple_backup_suffix = val && *val ? val : ".orig";

    if ((version_control = getenv ("PATCH_VERSION_CONTROL")))
      version_control_context = "$PATCH_VERSION_CONTROL";
    else if ((version_control = getenv ("VERSION_CONTROL")))
      version_control_context = "$VERSION_CONTROL";

    init_backup_hash_table ();
    init_files_to_delete ();
    init_files_to_output ();

    /* parse switches */
    Argc = argc;
    Argv = argv;
    get_some_switches();

    /* Make get_date() assume that context diff headers use UTC. */
    if (set_utc)
      setenv ("TZ", "UTC", 1);

    if (make_backups | backup_if_mismatch)
      backup_type = get_version (version_control_context, version_control);

    init_output (&outstate);
    if (outfile)
      outstate.ofp = open_outfile (outfile);

    /* Make sure we clean up in case of disaster.  */
    set_signals (false);

    /* When the file to patch is specified on the command line, allow that file
       to lie outside the current working tree.  Still doesn't allow to follow
       symlinks.  */
    if (inname)
      unsafe = true;

    if (inname && outfile)
      {
	/* When an input and an output filename is given and the patch is
	   empty, copy the input file to the output file.  In this case, the
	   input file must be a regular file (i.e., symlinks cannot be copied
	   this way).  */
	apply_empty_patch = true;
	file_type = S_IFREG;
	inerrno = -1;
      }
    for (
	open_patch_file (patchname);
	there_is_another_patch (! (inname || posixly_correct), &file_type)
	  || apply_empty_patch;
	reinitialize_almost_everything(),
	  skip_reject_file = false,
	  apply_empty_patch = false
    ) {					/* for each patch in patch file */
      int hunk = 0;
      int failed = 0;
      bool mismatch = false;
      char const *outname = NULL;

      if (skip_rest_of_patch)
	somefailed = true;

      if (have_git_diff != pch_git_diff ())
	{
	  if (have_git_diff)
	    {
	      output_files (NULL);
	      inerrno = -1;
	    }
	  have_git_diff = ! have_git_diff;
	}

      if (TMPREJNAME_needs_removal)
	{
	  if (rejfp)
	    {
	      fclose (rejfp);
	      rejfp = NULL;
	    }
	  remove_if_needed (TMPREJNAME, &TMPREJNAME_needs_removal);
	}
      if (TMPOUTNAME_needs_removal)
        {
	  if (outfd != -1)
	    {
	      close (outfd);
	      outfd = -1;
	    }
	  remove_if_needed (TMPOUTNAME, &TMPOUTNAME_needs_removal);
	}

      if (! skip_rest_of_patch && ! file_type)
	{
	  say ("File %s: can't change file type from 0%o to 0%o.\n",
	       quotearg (inname),
	       (unsigned int) (pch_mode (reverse) & S_IFMT),
	       (unsigned int) (pch_mode (! reverse) & S_IFMT));
	  skip_rest_of_patch = true;
	  somefailed = true;
	}

      if (! skip_rest_of_patch)
	{
	  if (outfile)
	    outname = outfile;
	  else if (pch_copy () || pch_rename ())
	    outname = pch_name (! reverse);
	  else
	    outname = inname;
	}

      if (pch_git_diff () && ! skip_rest_of_patch)
	{
	  struct stat outstat;
	  int outerrno = 0;

	  /* Try to recognize concatenated git diffs based on the SHA1 hashes
	     in the headers.  Will not always succeed for patches that rename
	     or copy files.  */

	  if (! strcmp (inname, outname))
	    {
	      if (inerrno == -1)
		inerrno = stat_file (inname, &instat);
	      outstat = instat;
	      outerrno = inerrno;
	    }
	  else
	    outerrno = stat_file (outname, &outstat);

	  if (! outerrno)
	    {
	      if (has_queued_output (&outstat))
		{
		  output_files (&outstat);
		  outerrno = stat_file (outname, &outstat);
		  inerrno = -1;
		}
	      if (! outerrno)
		set_queued_output (&outstat, true);
	    }
	}

      if (! skip_rest_of_patch)
	{
	  if (! get_input_file (inname, outname, file_type))
	    {
	      skip_rest_of_patch = true;
	      somefailed = true;
	    }
	}

      if (read_only_behavior != RO_IGNORE
	  && ! inerrno && ! S_ISLNK (instat.st_mode)
	  && safe_access (inname, W_OK) != 0)
	{
	  say ("File %s is read-only; ", quotearg (inname));
	  if (read_only_behavior == RO_WARN)
	    say ("trying to patch anyway\n");
	  else
	    {
	      say ("refusing to patch\n");
	      skip_rest_of_patch = true;
	      somefailed = true;
	    }
	}

      tmpoutst.st_size = -1;
      outfd = make_tempfile (&TMPOUTNAME, 'o', outname, 
			     O_WRONLY | binary_transput,
			     instat.st_mode & S_IRWXUGO);

/* src/common.h:95 */
XTERN char const * TMPOUTNAME;

/* src/patch.c:21 */
#define XTERN
#include <common.h>
#undef XTERN
#define XTERN extern
...

/* src/patch.c:337 */
int
main (int argc, char **argv)
{
    char const *val;
    bool somefailed = false;
    struct outstate outstate;
    struct stat tmpoutst;
    char numbuf[LINENUM_LENGTH_BOUND + 1];
    bool written_to_rejname = false;
    bool skip_reject_file = false;
    bool apply_empty_patch = false;
    mode_t file_type;
    int outfd = -1;
    bool have_git_diff = false;

    exit_failure = 2;
    set_program_name (argv[0]);
    init_time ();

    setbuf(stderr, serrbuf);

    bufsize = 8 * 1024;
    buf = xmalloc (bufsize);

    strippath = -1;

    val = getenv ("QUOTING_STYLE");
    {
      int i = val ? argmatch (val, quoting_style_args, 0, 0) : -1;
      set_quoting_style ((struct quoting_options *) 0,
			 i < 0 ? shell_quoting_style : (enum quoting_style) i);
    }

    posixly_correct = getenv ("POSIXLY_CORRECT") != 0;
    backup_if_mismatch = ! posixly_correct;
    patch_get = ((val = getenv ("PATCH_GET"))
		 ? numeric_string (val, true, "PATCH_GET value")
		 : 0);

    val = getenv ("SIMPLE_BACKUP_SUFFIX");
    simple_backup_suffix = val && *val ? val : ".orig";

    if ((version_control = getenv ("PATCH_VERSION_CONTROL")))
      version_control_context = "$PATCH_VERSION_CONTROL";
    else if ((version_control = getenv ("VERSION_CONTROL")))
      version_control_context = "$VERSION_CONTROL";

    init_backup_hash_table ();
    init_files_to_delete ();
    init_files_to_output ();

    /* parse switches */
    Argc = argc;
    Argv = argv;
    get_some_switches();

    /* Make get_date() assume that context diff headers use UTC. */
    if (set_utc)
      setenv ("TZ", "UTC", 1);

    if (make_backups | backup_if_mismatch)
      backup_type = get_version (version_control_context, version_control);

    init_output (&outstate);
    if (outfile)
      outstate.ofp = open_outfile (outfile);

    /* Make sure we clean up in case of disaster.  */
    set_signals (false);

    /* When the file to patch is specified on the command line, allow that file
       to lie outside the current working tree.  Still doesn't allow to follow
       symlinks.  */
    if (inname)
      unsafe = true;

    if (inname && outfile)
      {
	/* When an input and an output filename is given and the patch is
	   empty, copy the input file to the output file.  In this case, the
	   input file must be a regular file (i.e., symlinks cannot be copied
	   this way).  */
	apply_empty_patch = true;
	file_type = S_IFREG;
	inerrno = -1;
      }
    for (
	open_patch_file (patchname);
	there_is_another_patch (! (inname || posixly_correct), &file_type)
	  || apply_empty_patch;
	reinitialize_almost_everything(),
	  skip_reject_file = false,
	  apply_empty_patch = false
    ) {					/* for each patch in patch file */
      int hunk = 0;
      int failed = 0;
      bool mismatch = false;
      char const *outname = NULL;

      if (skip_rest_of_patch)
	somefailed = true;

      if (have_git_diff != pch_git_diff ())
	{
	  if (have_git_diff)
	    {
	      output_files (NULL);
	      inerrno = -1;
	    }
	  have_git_diff = ! have_git_diff;
	}

      if (TMPREJNAME_needs_removal)
	{
	  if (rejfp)
	    {
	      fclose (rejfp);
	      rejfp = NULL;
	    }
	  remove_if_needed (TMPREJNAME, &TMPREJNAME_needs_removal);
	}
      if (TMPOUTNAME_needs_removal)
        {
	  if (outfd != -1)
	    {
	      close (outfd);
	      outfd = -1;
	    }
	  remove_if_needed (TMPOUTNAME, &TMPOUTNAME_needs_removal);
	}

      if (! skip_rest_of_patch && ! file_type)
	{
	  say ("File %s: can't change file type from 0%o to 0%o.\n",
	       quotearg (inname),
	       (unsigned int) (pch_mode (reverse) & S_IFMT),
	       (unsigned int) (pch_mode (! reverse) & S_IFMT));
	  skip_rest_of_patch = true;
	  somefailed = true;
	}

      if (! skip_rest_of_patch)
	{
	  if (outfile)
	    outname = outfile;
	  else if (pch_copy () || pch_rename ())
	    outname = pch_name (! reverse);
	  else
	    outname = inname;
	}

      if (pch_git_diff () && ! skip_rest_of_patch)
	{
	  struct stat outstat;
	  int outerrno = 0;

	  /* Try to recognize concatenated git diffs based on the SHA1 hashes
	     in the headers.  Will not always succeed for patches that rename
	     or copy files.  */

	  if (! strcmp (inname, outname))
	    {
	      if (inerrno == -1)
		inerrno = stat_file (inname, &instat);
	      outstat = instat;
	      outerrno = inerrno;
	    }
	  else
	    outerrno = stat_file (outname, &outstat);

	  if (! outerrno)
	    {
	      if (has_queued_output (&outstat))
		{
		  output_files (&outstat);
		  outerrno = stat_file (outname, &outstat);
		  inerrno = -1;
		}
	      if (! outerrno)
		set_queued_output (&outstat, true);
	    }
	}

      if (! skip_rest_of_patch)
	{
	  if (! get_input_file (inname, outname, file_type))
	    {
	      skip_rest_of_patch = true;
	      somefailed = true;
	    }
	}

      if (read_only_behavior != RO_IGNORE
	  && ! inerrno && ! S_ISLNK (instat.st_mode)
	  && safe_access (inname, W_OK) != 0)
	{
	  say ("File %s is read-only; ", quotearg (inname));
	  if (read_only_behavior == RO_WARN)
	    say ("trying to patch anyway\n");
	  else
	    {
	      say ("refusing to patch\n");
	      skip_rest_of_patch = true;
	      somefailed = true;
	    }
	}

      tmpoutst.st_size = -1;
      outfd = make_tempfile (&TMPOUTNAME, 'o', outname, 
			     O_WRONLY | binary_transput,
			     instat.st_mode & S_IRWXUGO);
      if (outfd == -1)
	{
	  if (errno == ELOOP || errno == EXDEV)
	    {
	      say ("Invalid file name %s -- skipping patch\n", quotearg (outname));
	      skip_rest_of_patch = true;
	      skip_reject_file = true;
	      somefailed = true;
	    }
	  else
	    pfatal ("Can't create temporary file %s", TMPOUTNAME);
	}
      else
        TMPOUTNAME_needs_removal = true;
      if (diff_type == ED_DIFF) {
	outstate.zero_output = false;
	somefailed |= skip_rest_of_patch;
	do_ed_script (inname, TMPOUTNAME, &TMPOUTNAME_needs_removal, // 337
		      outstate.ofp);

/* src/pch.c:2473 */
void
do_ed_script (char const *inname, char const *outname,
	      bool *outname_needs_removal, FILE *ofp)
{
    static char const editor_program[] = EDITOR_PROGRAM;
	sprintf (buf, "%s %s%s", editor_program,
			verbosity == VERBOSE ? "" : "- ",
			outname);
	fflush (stdout);

	pid = fork();
	if (pid == -1)
	else if (pid == 0)
		execl ("/bin/sh", "sh", "-c", buf, (char *) 0);
```
</details>

### CVE-2019-16718~
radare2의 명령어 처리기에서, 악의적으로 조작된 심볼 이름을 포함한 바이너리 파일 분석 시, 심볼 정보를 출력하는 특정 명령어(`is*`)의 결과를 다시 명령으로 해석하는 과정에서 백틱(\`)으로 감싸인 심볼 이름이 쉘 명령으로 실행되는 **OS Command Injection 취약점**

1.  공격자가 심볼 이름에 쉘 메타문자(예: `` `!id` ``)가 포함된 악성 바이너리 파일을 준비하고, 사용자가 radare2에서 이 파일을 연 뒤 심볼 정보를 출력하는 명령어(예: `.is*`)를 실행합니다.

2.  `bin_symbols` 함수는 바이너리에서 악성 심볼 이름을 읽어(Source), 이를 포함한 radare2 플래그 설정 명령어(예: `f sym.imp.\`!id\``)를 문자열로 생성하여 출력합니다.

3.  명령어 맨 앞의 `.`(점)으로 인해, `cmd_interpret` 함수는 2단계에서 출력된 `"f sym.imp.\`!id\`"` 문자열을 새로운 명령으로 받아들여 `r_core_cmd0`를 통해 다시 radare2 명령어 처리기에 전달합니다.

4.  **(버그 발생)** 명령어 처리 중 `r_core_cmd_subst_i` 함수는 백틱(`` ` ``)으로 감싸인 부분을 발견하고, 그 내용이 `!`로 시작하는 것을 확인합니다. 이는 '내부의 `!id`를 시스템 명령으로 실행하고 그 결과로 대체하라'는 의미로 해석됩니다.

5.  `!` 문자로 인해 `id` 문자열은 `cmd_system` 콜백에 전달되고, 최종적으로 `r_sandbox_system` 함수를 통해 `system("id")` (Sink)가 호출되어 공격자가 심볼 이름에 숨겨둔 임의의 명령이 실행됩니다.

이 CVE 취약점을 유발하는 코드(sink:libr/core/cmd.c:3017)는 아래와 같다.

```c
/* libr/util/sandbox.c:185 */
R_API int r_sandbox_system (const char *x, int n) {
	if (enabled) {
		eprintf ("sandbox: system call disabled\n");
		return -1;
	}
#if LIBC_HAVE_FORK
#if LIBC_HAVE_SYSTEM
	if (n) {
		return system (x);
```

<details>
<summary>이 코드의 취약점을 표현하는 슬라이스</summary>

```c
libr/core/cmd_open.c:1412

		case 'd': // "ood" : reopen in debugger
			if (input[2] == 'r') { // "oodr"
				r_core_cmdf (core, "dor %s", input + 3);
				r_core_file_reopen_debug (core, "");
			} else if ('?' == input[2]) {
				r_core_cmd_help (core, help_msg_ood);
			} else {
				r_core_file_reopen_debug (core, input + 2);
			}

libr/core/cmd_open.c:907

R_API void r_core_file_reopen_debug(RCore *core, const char *args) {
 ...
		r_core_cmd0 (core, ".is*");

libr/core/cmd.c:4538

R_API int r_core_cmd0(RCore *core, const char *cmd) {
	return r_core_cmd (core, cmd, 0);
}

libr/core/cmd.c:4373

R_API int r_core_cmd(RCore *core, const char *cstr, int log) {
 ...
		ret = r_core_cmd_subst (core, rcmd);

libr/core/cmd.c:2418

static int r_core_cmd_subst(RCore *core, char *cmd) {
 ...
		ret = r_core_cmd_subst_i (core, cmd, colon, (rep == orep - 1) ? &tmpseek : NULL);


libr/core/cmd.c:3538

static int r_core_cmd_subst_i(RCore *core, char *cmd, char *colon, bool *tmpseek) {
 ...

	rc = cmd? r_cmd_call (core->rcmd, r_str_trim_head (cmd)): false;


libr/core/cmd_api.c:244

R_API int r_cmd_call(RCmd *cmd, const char *input) {
 ... 
                // libr/core/cmd.d:4750
		//	struct {
		//		const char *cmd;
		//		const char *description;
		//		r_cmd_callback (cb);
		//		void (*descriptor_init)(RCore *core);
		//	} cmds[] = {
		//           ...
		//      		{".",        "interpret", cmd_interpret},

		c = cmd->cmds[((ut8)input[0]) & 0xff]; // input[0] == '.'
		if (c && c->callback) {
			const char *inp = (*input)? input + 1: ""; // input+1은 점 다음 명령
			ret = c->callback (cmd->data, inp);

libr/core/cmd.c:1108,1213

static int cmd_interpret(void *data, const char *input) {
 ...
	ptr = str = r_core_cmd_str (core, inp);


libr/core/cmd.c:4618, 4623

R_API char *r_core_cmd_str(RCore *core, const char *cmd) {
  ...
	if (r_core_cmd (core, cmd, 0) == -1) {

libr/core/cmd.c:4301,4373

R_API int r_core_cmd(RCore *core, const char *cstr, int log) {
   ...
            r_str_cpy (cmd, cstr);
   ...
            for (rcmd = cmd;;) {
		ptr = strchr (rcmd, '\n');
		if (ptr) {
			*ptr = '\0';
		}
		ret = r_core_cmd_subst (core, rcmd);


libr/core/cmd.c:2316,2418

static int r_core_cmd_subst(RCore *core, char *cmd) {
 ...
		ret = r_core_cmd_subst_i (core, cmd, colon, (rep == orep - 1) ? &tmpseek : NULL);

   // r_core_cmd_subst_i를 재귀 호출하고
   // r_cmd_call을 재귀 호출하고

   // cmd->cmds[ ... ]에서 이번에는 cmd.c:4765에서
   //  ( '.'이 아니라 ) 'i' 명령어를 인덱스로
   // cmd_info 함수를 찾아 호출한다!!!

   //	struct {
   //		const char *cmd;
   //		const char *description;
   //		r_cmd_callback (cb);
   //		void (*descriptor_init)(RCore *core);
   //	} cmds[] = {
   //            ...
   //     	{"info",     "get file info", cmd_info, cmd_info_init},

   //		c = cmd->cmds[((ut8)input[0]) & 0xff];
   //		if (c && c->callback) {
   //			const char *inp = (*input)? input + 1: "";
   //			ret = c->callback (cmd->data, inp);


// libr/core/cmd_info.c:441,780,793  "is*"
static int cmd_info(void *data, const char *input) {
 ...
		case 's': { // "is"
			RBinObject *obj = r_bin_cur_object (core->bin); // 바이너리 가져오기
                        ...
                   else { // "is*"
				RBININFO ("symbols", R_CORE_BIN_ACC_SYMBOLS, input + 1, 
                                 (obj && obj->symbols)? r_list_length (obj->symbols): 0);
		   }

// RBININFO 매크로 확장
// r_core_bin_info() 함수 호출

   if (is_array) { 
      if (is_array == 1) { is_array++; } else { r_cons_printf (",");} 
      r_cons_printf ("\"%s\":","symbols"); 
   } 
   if ((obj && obj->symbols)? r_list_length (obj->symbols): 0) { 
      playMsg (core, "symbols", (obj && obj->symbols)? r_list_length (obj->symbols): 0);
   } 
   r_core_bin_info (core, 0x040, mode, va, ((void *)0), input + 1);


// libr/core/cbin.c:3745, 3811
R_API int r_core_bin_info(RCore *core, int action, int mode, int va, RCoreBinFilter *filter, const char *chksum) {
   ...
	if ((action & R_CORE_BIN_ACC_SYMBOLS)) { // 6s
		ret &= bin_symbols (core, mode, loadaddr, va, at, name, false, chksum);
	}


// libr/core/cbin.c:2022,2216  심볼 플래그를 출력 flag sym.n1 0xc1 8 ....
static int bin_symbols(RCore *r, int mode, ut64 laddr, int va, ut64 at, const char *name, bool exponly, const char *args) {
  ...
	r_cons_printf ("\"f %s%s%s %u 0x%08" PFMT64x "\"\n",
	   r->bin->prefix ? r->bin->prefix : "", r->bin->prefix ? "." : "",
		flagname, symbol->size, addr);

// cmd->cmds['i']  is*의 callback 함수 호출 자리로 돌아가고
// cmd->cmds['.']  .의 callback 함수 호출 자리로 돌아간다

// libr/core/cmd.c:4373으로 리턴
// is* 실행 결과로 나온 "flag sym.n1 0xc0 8\nflag sym.n2 0xff 2\n ..."
//  문자열이rcmd에 append되고
//  아래 for문에 의해 '\n'로 strchr로 찾은 문자열을
//  다음 명령어로 반복 실행 

	for (rcmd = cmd;;) {
		ptr = strchr (rcmd, '\n');
		if (ptr) {
			*ptr = '\0';
		}
		ret = r_core_cmd_subst (core, rcmd);
		if (ret == -1) {
			eprintf ("|ERROR| Invalid command '%s' (0x%02x)\n", rcmd, *rcmd);
			break;
		}
		if (!ptr) {
			break;
		}
		rcmd = ptr + 1;
	}

// 그 결과 is*로 출력한 flag 명령어들이 실행되고
// 심볼에 `!id`가 포함되어 있는 flag 명령어가 있으면
// r_core_cmd_subst_i() 함수에서 
// `...`과 ! 쉘 명령어를 인식하고
// cmd->cmds[ '!' ]의 콜백 함수를 실행 

libr/core/cmd.c:2506,2990,3016-3018

static int r_core_cmd_subst_i(RCore *core, char *cmd, char *colon, bool *tmpseek) {
 ...
	/* sub commands */
	ptr = strchr (cmd, '`');

 ...
        if (ptr[1] == '!') {
	   str = r_core_cmd_str_pipe (core, ptr + 1);
        } else {

libr/core/cmd.c:4547, 4585

R_API char *r_core_cmd_str_pipe(RCore *core, const char *cmd) {
 ...
   r_core_cmd_subst (core, _cmd);

   // r_core_cmd_subst_i()를 호출
   // r_core_cmd_call()을 호출
   // cmd->cmds['!']를 참조하여 cmd_system()를 호출

/* libr/core/cmd.c:2086 */
static int cmd_system(void *data, const char *input) {
	RCore *core = (RCore*)data;
	ut64 n;
	int ret = 0;
	switch (*input) {
	default:
		n = atoi (input);
		if (*input == '0' || n > 0) {
		} else {
			char *cmd = r_core_sysenv_begin (core, input);
			if (cmd) {
				void *bed = r_cons_sleep_begin ();
				ret = r_sys_cmd (cmd);

/* libr/util/sys.c:799 */
R_API int r_sys_cmd(const char *str) {
	if (r_sandbox_enable (0)) {
		return false;
	}
	return r_sandbox_system (str, 1);

/* libr/util/sandbox.c:185 */
R_API int r_sandbox_system (const char *x, int n) {
	if (enabled) {
		eprintf ("sandbox: system call disabled\n");
		return -1;
	}
#if LIBC_HAVE_FORK
#if LIBC_HAVE_SYSTEM
	if (n) {
		return system (x);
```
</details>