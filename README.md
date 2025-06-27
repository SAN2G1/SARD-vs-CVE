# SARD-vs-CVE
AI가 SARD는 잘 탐지하지만 CVE는 놓치는 이유를 분석하기 위해 두 데이터를 비교합니다.

## 개요

...                                                      |

## 세부 사항
### CWE-134: FSB(Format String Bug)
#### CVE-2011-4930
##### 취약점 설명
분산 컴퓨팅 도구 HTCondor에서 입력받은 사용자 계정 정보를 sprintf의 포맷 문자열로 그대로 사용하면서 발생한 포맷 스트링 취약점
- Source: socket에서 들어오는 유저 네임
- Sink: source를 포맷으로 사용해 호출되는 `sprintf()`

이 CVE 취약점을 유발하는 코드(src/condorr_credd/credd.cpp:266)는 아래와 같다.

```
if (!socket->code(name)) {
    dprintf (D_ALWAYS, "Error receiving credential name\n"); 
    goto EXIT;
  }

  user = socket->getFullyQualifiedUser();
  dprintf (D_ALWAYS, "Authenticated as %s\n", user);

  if (strchr (name, ':')) {
    // The name is of the form user:name
    // This better be a super-user!
    // TODO: Check super-user's list

    // Owner is the first part
    owner = strdup (name);
    char * pColon = strchr (owner, ':');
    *pColon = '\0';
    
    // Name is the second part
    sprintf (name, (char*)(pColon+sizeof(char)));
```

이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.

<details>
<summary>이상적인 슬라이스 보기</summary>

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

</details>

##### SARD는 잘 탐지하는데 이 CVE는 탐지 못했던 이유
Joern이 취약점 sink인 sprintf를 노드로 인식하지 못해 슬라이스가 생성되지 않아 취약점 예측이 불가능

#### CVE-2015-8617
##### 취약점 설명
php 인터프리터에서 존재하지 않는 클래스명에 대한 예외 처리 시, 해당 클래스 명을 포맷 문자열로 그대로 사용하면서 발생한 포맷 스트링 취약점
- Source: 사용자 입력한 클래스명
- Sink: source를 포맷으로 사용해 호출되는 `zend_vspprintf()`

[PoC 예시](https://bugs.php.net/bug.php?id=71105): `<?php $name="%n%n%n"; $name::doSomething(); ?>`

이 CVE 취약점을 유발하는 코드(sink:zend_execute_API.c:221)는 아래와 같다.
```c
static void zend_throw_or_error(int fetch_type, zend_class_entry *exception_ce, const char *format, ...) {
	va_list va;
	char *message = NULL;

	va_start(va, format);
	zend_vspprintf(&message, 0, format, va);

	if (fetch_type & ZEND_FETCH_CLASS_EXCEPTION) {
		zend_throw_error(exception_ce, message);
}
```
이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.


<details>
<summary>이상적인 슬라이스 보기</summary>

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

/* Zend/zend.c:632 */
int zend_startup(zend_utility_functions *utility_functions, char **extensions) /* {{{ */
{
#ifdef ZTS
	zend_compiler_globals *compiler_globals;
	zend_executor_globals *executor_globals;
	extern ZEND_API ts_rsrc_id ini_scanner_globals_id;
	extern ZEND_API ts_rsrc_id language_scanner_globals_id;
	ZEND_TSRMLS_CACHE_UPDATE();
#else
	extern zend_ini_scanner_globals ini_scanner_globals;
	extern zend_php_scanner_globals language_scanner_globals;
#endif

	start_memory_manager();

	virtual_cwd_startup(); /* Could use shutdown to free the main cwd but it would just slow it down for CGI */

#if defined(__FreeBSD__) || defined(__DragonFly__)
	/* FreeBSD and DragonFly floating point precision fix */
	fpsetmask(0);
#endif

	zend_startup_strtod();
	zend_startup_extensions_mechanism();

	/* Set up utility functions and values */
	zend_error_cb = utility_functions->error_function;
	zend_printf = utility_functions->printf_function;
	zend_write = (zend_write_func_t) utility_functions->write_function;
	zend_fopen = utility_functions->fopen_function;
	if (!zend_fopen) {
		zend_fopen = zend_fopen_wrapper;
	}
	zend_stream_open_function = utility_functions->stream_open_function;
	zend_message_dispatcher_p = utility_functions->message_handler;
#ifndef ZEND_SIGNALS
	zend_block_interruptions = utility_functions->block_interruptions;
	zend_unblock_interruptions = utility_functions->unblock_interruptions;
#endif
	zend_get_configuration_directive_p = utility_functions->get_configuration_directive;
	zend_ticks_function = utility_functions->ticks_function;
	zend_on_timeout = utility_functions->on_timeout;
	zend_vspprintf = utility_functions->vspprintf_function;

/* main/main.c:2058 */
int php_module_startup(sapi_module_struct *sf, zend_module_entry *additional_modules, uint num_additional_modules)
{
	zend_utility_functions zuf;
    zuf.vspprintf_function = vspprintf;
	zuf.vstrpprintf_function = vstrpprintf;
	zuf.getenv_function = sapi_getenv;
	zuf.resolve_path_function = php_resolve_path_for_zend;
	zend_startup(&zuf, NULL);

/* main/spprintf.c:847 */
PHPAPI size_t vspprintf(char **pbuf, size_t max_len, const char *format, va_list ap) /* {{{ */
{
	smart_string buf = {0};

	/* since there are places where (v)spprintf called without checking for null,
	   a bit of defensive coding here */
	if(!pbuf) {
		return 0;
	}
	xbuf_format_converter(&buf, 1, format, ap);
}

/* main/spprintf.c:744 */
static void xbuf_format_converter(void *xbuf, zend_bool is_char, const char *fmt, va_list ap) /* {{{ */
{
	...
	while (*fmt) {
		if (*fmt != '%') {
			INS_CHAR(xbuf, *fmt, is_char);
		} else {
			/*
			 * Default variable settings
			 */
			adjust = RIGHT;
			alternate_form = print_sign = print_blank = NO;
			pad_char = ' ';
			prefix_char = NUL;
			free_zcopy = 0;

			fmt++;

			/*
			 * Try to avoid checking for flags, width or precision
			 */
			if (isascii((int)*fmt) && !islower((int)*fmt)) {
				/*
				 * Recognize flags: -, #, BLANK, +
				 */
				for (;; fmt++) {
					if (*fmt == '-')
						adjust = LEFT;
					else if (*fmt == '+')
						print_sign = YES;
					else if (*fmt == '#')
						alternate_form = YES;
					else if (*fmt == ' ')
						print_blank = YES;
					else if (*fmt == '0')
						pad_char = '0';
					else
						break;
				}

				/*
				 * Check if a width was specified
				 */
				if (isdigit((int)*fmt)) {
					STR_TO_DEC(fmt, min_width);
					adjust_width = YES;
				} else if (*fmt == '*') {
					min_width = va_arg(ap, int);
					fmt++;
					adjust_width = YES;
					if (min_width < 0) {
						adjust = LEFT;
						min_width = -min_width;
					}
				} else
					adjust_width = NO;

				/*
				 * Check if a precision was specified
				 */
				if (*fmt == '.') {
					adjust_precision = YES;
					fmt++;
					if (isdigit((int)*fmt)) {
						STR_TO_DEC(fmt, precision);
					} else if (*fmt == '*') {
						precision = va_arg(ap, int);
						fmt++;
						if (precision < 0)
							precision = 0;
					} else
						precision = 0;

					if (precision > FORMAT_CONV_MAX_PRECISION) {
						precision = FORMAT_CONV_MAX_PRECISION;
					}
				} else
					adjust_precision = NO;
			} else
				adjust_precision = adjust_width = NO;

			/*
			 * Modifier check
			 */
            switch (*fmt) {
                ...
				case 'n':
					*(va_arg(ap, int *)) = is_char? (int)((smart_string *)xbuf)->len : (int)ZSTR_LEN(((smart_str *)xbuf)->s);
```

</details>

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
##### 취약점 설명
내부 시스템 로그를 외부 로그 서버로 전송하는 rsyslog에서 ZeroMQ 연결 시, 외부에서 설정된 메시지 큐 연결 정보가 그대로 포맷 문자열로 사용되어 발생한 포맷 스트링 취약점

1. rsyslogd가 시작될 때 외부 로그 서버 연결 정보가 저장된 설정 파일을 읽고,
    ```conf
    # 출처: https://www.rsyslog.com/quick-guide-to-omzmq3
    # description에 %n을 넣으면 format string bug 발생 !

    *.* action(type="omzmq3" sockType="PUB" action="BIND" description="tcp://*:11514" template="any_message_template")

    ```
2. newActInst 모듈 함수를 호출해서 pData의 description 관련 필드에 포맷 에러와 관련된 악성 스트링을 설정하고 해당 모듈을 위한 액션 큐와 워커 생성
3. zmq 관련 메시지가 수신되어 처리될 때, doAction 모듈 함수나, tryResume 모듈 함수가 호출
4. socket 통신이 처음이면 초기화를 하는데,
5. 그 과정에서 zsocket_connect를 호출할 때, description 스트링을 포맷 스트링으로 사용해서 취약점이 발생한다.

이 CVE 취약점을 유발하는 코드(sink:contrib/omzmq3/omzmq3.c:245)는 아래와 같다.
```c
static rsRetVal initZMQ(instanceData* pData) {
    DEFiRet;
    if (NULL == s_context) {
    pData->socket = zsocket_new(s_context, pData->type);
    if (NULL == pData->socket) {
    if (pData->action == ACTION_BIND) {
        if(-1 == zsocket_bind(pData->socket, (char*)pData->description)) {
        // CZMQ_EXPORT int zsocket_bind(void *self, const char *format, ...); @czmq.h
```
이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.

<details>
<summary>이상적인 슬라이스 보기</summary>

```c
/* rsyslogd.c:1407 */
rsconf_t *ourConf = NULL;
uchar *ConfFile = (uchar*) "/etc/rsyslog.conf";

static void
initAll(int argc, char **argv)
{
	...
	localRet = rsconf.Load(&ourConf, ConfFile);

/* runtime/rsconf.c:1391 */
BEGINobjQueryInterface(rsconf)
CODESTARTobjQueryInterface(rsconf)
	if(pIf->ifVersion != rsconfCURR_IF_VERSION) { /* check for current version, increment on each change */
		ABORT_FINALIZE(RS_RET_INTERFACE_NOT_SUPPORTED);
	}

	/* ok, we have the right interface, so let's fill it
	 * Please note that we may also do some backwards-compatibility
	 * work here (if we can support an older interface version - that,
	 * of course, also affects the "if" above).
	 */
	pIf->Destruct = rsconfDestruct;
	pIf->DebugPrint = rsconfDebugPrint;
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
	char namebuf[256];
	rsRetVal localRet;
	if((cnfstmt = cnfstmtNew(S_ACT)) == NULL) 
		goto done;
	localRet = actionNewInst(lst, &cnfstmt->d.act);

/* action.c:1969 */
rsRetVal
actionNewInst(struct nvlst *lst, action_t **ppAction)
{
	struct cnfparamvals *paramvals;
	modInfo_t *pMod;
	uchar *cnfModName = NULL;
	omodStringRequest_t *pOMSR;
	void *pModData;
	action_t *pAction;
	DEFiRet;

	paramvals = nvlstGetParams(lst, &pblk, NULL);
	if(paramvals == NULL) {
		ABORT_FINALIZE(RS_RET_PARAM_ERROR);
	}
	dbgprintf("action param blk after actionNewInst:\n");
	cnfparamsPrint(&pblk, paramvals);
	cnfModName = (uchar*)es_str2cstr(paramvals[cnfparamGetIdx(&pblk, ("type"))].val.d.estr, NULL);
	if((pMod = module.FindWithCnfName(loadConf, cnfModName, eMOD_OUT)) == NULL) {
		errmsg.LogError(0, RS_RET_MOD_UNKNOWN, "module name '%s' is unknown", cnfModName);
		ABORT_FINALIZE(RS_RET_MOD_UNKNOWN);
	}
	CHKiRet(pMod->mod.om.newActInst(cnfModName, lst, &pModData, &pOMSR));
        /* omzmq3.c:380 */
        BEGINnewActInst
            struct cnfparamvals *pvals;
            int i;
        CODESTARTnewActInst
            if ((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
                ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
            }

            CHKiRet(createInstance(&pData));
            setInstParamDefaults(pData);

            CODE_STD_STRING_REQUESTnewActInst(1)
            for (i = 0; i < actpblk.nParams; ++i) {
                if (!pvals[i].bUsed)
                    continue;
                if (!strcmp(actpblk.descr[i].name, "description")) {
                    pData->description = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
                        // 문제가 되는 description이 여기서 설정됨.
    
	if((iRet = addAction(&pAction, pMod, pModData, pOMSR, paramvals, lst)) == RS_RET_OK) { 

/* action.c:1903 */
rsRetVal
addAction(action_t **ppAction, modInfo_t *pMod, void *pModData,
	  omodStringRequest_t *pOMSR, struct cnfparamvals *actParams,
	  struct nvlst * const lst)
{
	DEFiRet;
	int i;
	int iTplOpts;
	uchar *pTplName;
	action_t *pAction;
	char errMsg[512];

	assert(ppAction != NULL);
	assert(pMod != NULL);
	assert(pOMSR != NULL);
	DBGPRINTF("Module %s processes this action.\n", module.GetName(pMod));

	CHKiRet(actionConstruct(&pAction)); /* create action object first */

	pAction->pMod = pMod;
	pAction->pModData = pModData;

	CHKiRet(actionConstructFinalize(pAction, lst));

/* action.c:509 */
rsRetVal
actionConstructFinalize(action_t *__restrict__ const pThis, struct nvlst *lst)
{
	DEFiRet;
	uchar pszAName[64]; /* friendly name of our action */

    ...

	/* create queue */
	CHKiRet(qqueueConstruct(&pThis->pQueue, cs.ActionQueType, 1, cs.iActionQueueSize,
					processBatchMain));

// 메시지 큐에 메시지가 쌓이면,

/* runtime/wti.c:365 */
rsRetVal
wtiWorker(wti_t *__restrict__ const pThis)
{
	...
	d_pthread_mutex_lock(pWtp->pmutUsr);
	while(1) { /* loop will be broken below */
		if(pWtp->pfRateLimiter != NULL) { /* call rate-limiter, if defined */
			pWtp->pfRateLimiter(pWtp->pUsr);
		}
		terminateRet = wtpChkStopWrkr(pWtp, MUTEX_ALREADY_LOCKED);
		if(terminateRet == RS_RET_TERMINATE_NOW) {

		/* try to execute and process whatever we have */
		localRet = pWtp->pfDoWork(pWtp->pUsr, pThis);

/* runtime/obj-types.h:139 */
#define DEFpropSetMethFP(obj, prop, dataType)\
	rsRetVal obj##Set##prop(obj##_t *pThis, dataType)\
	{ \
		/* DEV debug: dbgprintf("%sSet%s()\n", #obj, #prop); */\
		pThis->prop = pVal; \
		return RS_RET_OK; \
	}

/* runtime/wtp.c:531 */
DEFpropSetMethFP(wtp, pfDoWork, rsRetVal(*pVal)(void*, void*))

/* runtime/obj-types.h:146 */
#define PROTOTYPEpropSetMethFP(obj, prop, dataType)\
	rsRetVal obj##Set##prop(obj##_t *pThis, dataType)

/* runtime/wtp.h:91 */
PROTOTYPEpropSetMethFP(wtp, pfDoWork, rsRetVal(*pVal)(void*, void*));

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
	if(iRet == RS_RET_FILE_NOT_FOUND) {
	if (iRet != RS_RET_OK) {

	/* we now have a non-idle batch of work, so we can release the queue mutex and process it */
	d_pthread_mutex_unlock(pThis->mut);
	bNeedReLock = 1;

	/* report errors, now that we are outside of queue lock */
	if(skippedMsgs > 0) {

	/* at this spot, we may be cancelled */
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &iCancelStateSave);


	pWti->pbShutdownImmediate = &pThis->bShutdownImmediate;
	CHKiRet(pThis->pConsumer(pThis->pAction, &pWti->batch, pWti));

/* 
// runtime/queue.c:1374
rsRetVal qqueueConstruct(qqueue_t **ppThis, queueType_t qType, int iWorkerThreads,
	int iMaxQueueSize, rsRetVal (*pConsumer)(void*, batch_t*, wti_t*))

// action.c:509
rsRetVal
actionConstructFinalize(action_t *__restrict__ const pThis, struct nvlst *lst)
{
	DEFiRet;
	uchar pszAName[64];

    ...

	CHKiRet(qqueueConstruct(&pThis->pQueue, cs.ActionQueType, 1, cs.iActionQueueSize,
					processBatchMain));

이 코드는 qqueueConstruct 함수를 호출하여, 큐(queue) 자료구조를 초기화(생성)하는 부분입니다.

각 인자의 의미는 다음과 같습니다:

&pThis->pQueue : 생성된 큐 객체를 저장할 포인터(큐의 주소)
cs.ActionQueType : 큐의 타입(큐가 어떤 동작을 하는지 지정)
1 : 큐의 동작 모드 또는 플래그(예: 동기/비동기, 활성화 여부 등, 구현에 따라 다름)
cs.iActionQueueSize : 큐의 크기(큐에 저장할 수 있는 최대 항목 수)
processBatchMain : 큐에 저장된 항목을 처리할 함수(콜백 함수)
			
*/

/* action.c:1416 */
static rsRetVal
processBatchMain(void *__restrict__ const pVoid,
	batch_t *__restrict__ const pBatch,
	wti_t *__restrict__ const pWti)
{
	action_t *__restrict__ const pAction = (action_t*__restrict__ const) pVoid;
	int i;
	struct syslogTime ttNow;
	DEFiRet;

	wtiResetExecState(pWti, pBatch);
	/* indicate we have not yet read the date */
	ttNow.year = 0;

	for(i = 0 ; i < batchNumMsgs(pBatch) && !*pWti->pbShutdownImmediate ; ++i) {
		if(batchIsValidElem(pBatch, i)) {
			/* we do not check error state below, because aborting would be
			 * more harmful than continuing.
			 */
			processMsgMain(pAction, pWti, pBatch->pElem[i].pMsg, &ttNow);

/* action.c:1382 */
static rsRetVal
processMsgMain(action_t *__restrict__ const pAction,
	wti_t *__restrict__ const pWti,
	smsg_t *__restrict__ const pMsg,
	struct syslogTime *ttNow)
{
	DEFiRet;

	CHKiRet(prepareDoActionParams(pAction, pWti, pMsg, ttNow));

	if(pAction->isTransactional) {
		pWti->actWrkrInfo[pAction->iActionNbr].pAction = pAction;
		DBGPRINTF("action '%s': is transactional - executing in commit phase\n", pAction->pszName);
		actionPrepare(pAction, pWti);
		iRet = getReturnCode(pAction, pWti);
		FINALIZE;
	}

	iRet = actionProcessMessage(pAction,
				    pWti->actWrkrInfo[pAction->iActionNbr].p.nontx.actParams,
				    pWti);

/* action.c:1171 */
static rsRetVal actionProcessMessage(action_t * const pThis, void *actParams, wti_t * const pWti)
{
	DEFiRet;

	CHKiRet(actionPrepare(pThis, pWti));
	if(pThis->pMod->mod.om.SetShutdownImmdtPtr != NULL)
		pThis->pMod->mod.om.SetShutdownImmdtPtr(pThis->pModData, pWti->pbShutdownImmediate);
	if(getActionState(pWti, pThis) == ACT_STATE_ITX)
		CHKiRet(actionCallDoAction(pThis, actParams, pWti));

/* action.c:1128 */
static rsRetVal actionCallDoAction(action_t *__restrict__ const pThis, 	actWrkrIParams_t *__restrict__ onst iparams, wti_t *__restrict__ const pWti) {
	void *param[CONF_OMOD_NUMSTRINGS_MAXSIZE];
	int i;
	DEFiRet;

	DBGPRINTF("entering actionCalldoAction(), state: %s, actionNbr %d\n",
		  getActStateName(pThis, pWti), pThis->iActionNbr);

	iRet = pThis->pMod->mod.om.doAction(param,
				            pWti->actWrkrInfo[pThis->iActionNbr].actWrkrData);

/* runtime/module-template.h:280 */
#define BEGINdoAction \
static rsRetVal doAction(void * pMsgData, wrkrInstanceData_t __attribute__((unused)) *pWrkrData)\
{\
	uchar **ppString = (uchar **) pMsgData; \
	DEFiRet;

/* contrib/omzmq3/omzmq3.c:359 */
BEGINdoAction
	instanceData *pData = pWrkrData->pData;
CODESTARTdoAction
	pthread_mutex_lock(&mutDoAct);
	iRet = writeZMQ(ppString[0], pData);

/* contrib/omzmq3/omzmq3.c:268 */
rsRetVal writeZMQ(uchar* msg, instanceData* pData) {
	DEFiRet;

    /* initialize if necessary */
    if(NULL == pData->socket)
		CHKiRet(initZMQ(pData));

/* contrib/omzmq3/omzmq3.c:245 */
static rsRetVal initZMQ(instanceData* pData) {
    DEFiRet;
    if (NULL == s_context) {
    pData->socket = zsocket_new(s_context, pData->type);
    if (NULL == pData->socket) {
    if (pData->action == ACTION_BIND) {
        if(-1 == zsocket_bind(pData->socket, (char*)pData->description)) {

```

</details>

##### SARD는 잘 탐지하는데 이 CVE는 탐지 못했던 이유

###### 설정 파일 파서(Parser) 분석의 한계
Ksign 슬라이서와 같은 C/C++ 코드 기반 정적 분석 도구는 .l, .y 파일과 연계된 파서의 동작을 해석하지 못하는 한계를 가집니다. 이로 인해, CVE-2017-12588과 같이 외부 설정 파일에서 시작되어 파서의 콜백 함수를 통해 C 코드로 데이터가 유입되는 유형의 취약점은 데이터 흐름의 시작점을 놓치게 되어 탐지하지 못합니다. 이는 SARD 데이터셋처럼 순수 C 코드로만 구성된 환경에서는 드러나지 않는 문제입니다.


###### 복잡한 매크로!
CVE 코드에서는 DEFpropSetMethFP와 같은 매크로가 함수를 동적으로 생성합니다. wtpSetpfDoWork라는 핵심 함수는 개발자가 직접 작성한 것이 아니라, 매크로와 ## 연산자에 의해 **전처리(Pre-processing) 과정에서 만들어지는 '가상의 함수'**입니다.

정적 분석기는 소스 코드에서 wtpSetpfDoWork 함수의 정의를 찾지 못해 호출 관계(Call Graph)를 구성하는 데 실패합니다. 호출 관계가 끊어지면, 이 함수 내부에서 일어나는 핵심 데이터 흐름(콜백 함수 주소 할당) 또한 추적할 수 없게 됩니다. 결과적으로, 소스(Source)와 싱크(Sink)를 잇는 슬라이스가 중간에 완전히 끊어져 취약점을 탐지할 수 없습니다.

```c
/* runtime/wti.c:365 */
rsRetVal
wtiWorker(wti_t *__restrict__ const pThis)
{
	...
	d_pthread_mutex_lock(pWtp->pmutUsr);
	while(1) { /* loop will be broken below */
		if(pWtp->pfRateLimiter != NULL) { /* call rate-limiter, if defined */
			pWtp->pfRateLimiter(pWtp->pUsr);
		}
		terminateRet = wtpChkStopWrkr(pWtp, MUTEX_ALREADY_LOCKED);
		if(terminateRet == RS_RET_TERMINATE_NOW) {

		/* try to execute and process whatever we have */
		localRet = pWtp->pfDoWork(pWtp->pUsr, pThis);

/* runtime/obj-types.h:139 */
#define DEFpropSetMethFP(obj, prop, dataType)\
	rsRetVal obj##Set##prop(obj##_t *pThis, dataType)\
	{ \
		/* DEV debug: dbgprintf("%sSet%s()\n", #obj, #prop); */\
		pThis->prop = pVal; \
		return RS_RET_OK; \
	}

/* runtime/wtp.c:531 */
DEFpropSetMethFP(wtp, pfDoWork, rsRetVal(*pVal)(void*, void*))

/* runtime/obj-types.h:146 */
#define PROTOTYPEpropSetMethFP(obj, prop, dataType)\
	rsRetVal obj##Set##prop(obj##_t *pThis, dataType)

/* runtime/wtp.h:91 */
PROTOTYPEpropSetMethFP(wtp, pfDoWork, rsRetVal(*pVal)(void*, void*));

/* runtime/queue.c:2405 */
rsRetVal
qqueueStart(qqueue_t *pThis) /* this is the ConstructionFinalizer */
{
	...

	CHKiRet(wtpSetpfDoWork		(pThis->pWtpReg, (rsRetVal (*)(void *pUsr, void *pWti)) ConsumerReg));
```

###### 실행 단계가 분리되어 있어 취약점을 하나의 슬라이스로 표현 불가능
실행 단계 분리로 인한 탐지 실패 요약
정적 분석기가 이 취약점을 탐지하지 못하는 이유는, 데이터가 오염되는 시점과 사용되는 시점이 완전히 분리되어 있기 때문입니다.

1단계 (저장): 프로그램이 시작될 때, 악의적인 설정값(Source)은 특정 데이터 구조체에 담겨 메모리(액션 큐)에 저장됩니다.

2단계 (사용): 이후 프로그램이 실행 중일 때, 별개의 워커 스레드가 큐에서 이 데이터를 꺼내와 취약한 함수(Sink)에서 사용합니다.

정적 분석기는 이렇게 시간과 실행 흐름(스레드)이 단절된 '저장' 시점과 '사용' 시점을 하나의 연속된 데이터 흐름으로 연결하지 못합니다. 데이터가 큐에 들어갔다가 나오는 복잡한 과정을 추적하지 못해, 결국 Source와 Sink를 잇는 분석 경로(Slice)가 중간에 끊어지므로 취약점을 놓치게 됩니다.

##### 그 외 CPG(Code Property Graph)로 표현 불가능한 콜백 함수 호출
이건 SARD도 탐지하지 못하는 사례

**SARD Test Case Flow Variants 44 and 65**
Data passed as an argument from one function to a function in
the same source file called via a function pointer

### CWE-400: RE(Resource Exhaustion)
#### CVE-2017-11142
PHP가 POST 요청을 처리하는 add_post_vars 함수에서, 처리된 데이터의 위치가 올바르게 갱신되지 않아, memchr 함수가 이미 스캔한 데이터를 포함한 전체 버퍼를 반복적으로 재검색하여 CPU 자원을 고갈시키는 서비스 거부(DoS) 취약점

1. PHP 엔진이 HTTP POST 요청을 받아 php_std_post_handler 함수를 호출합니다. 이 함수는 while 루프를 돌며 POST 데이터를 청크(chunk) 단위로 읽어 post_data 버퍼에 추가합니다.
2. php_std_post_handler는 루프를 돌 때마다 add_post_vars 함수를 호출하여 버퍼에 쌓인 데이터의 변수 파싱을 시도합니다.
3. (버그 발생) 하지만 add_post_vars 함수는 호출될 때마다 처리 위치 포인터(vars->ptr)를 항상 버퍼의 맨 처음(vars->str.c)으로 초기화합니다. 이로 인해 이전에 파싱을 시도했던 부분을 기억하지 못하고, 매번 누적된 데이터 전체를 새로 파싱하게 됩니다.
4. add_post_vars 내부에서 호출되는 add_post_var 함수는 변수 구분자인 &를 찾기 위해 memchr를 사용합니다. 버그로 인해 memchr는 이전에 이미 & 문자가 없음을 확인했던 영역까지 포함하여, 점점 커지는 전체 버퍼를 처음부터 끝까지 반복적으로 스캔하게 됩니다.
5. 공격자는 & 문자 없이 매우 큰 단일 변수(예: a=AAAA...)를 전송하여 이 시나리오를 유발합니다. 버퍼가 계속 커지고(8KB, 16KB, 24KB...) memchr의 스캔 범위가 그에 따라 선형적으로 증가하면서, CPU 사용량이 100%에 도달해 서비스가 마비됩니다. 변수가 하나이므로 max_input_vars 제한은 쉽게 우회됩니다.

이 CVE 취약점을 유발하는 코드(sink:php_variables.c:253, memset)는 아래와 같다.
```
static zend_bool add_post_var(zval *arr, post_var_data_t *var, zend_bool eof TSRMLS_DC){
	if (var->ptr >= var->end) {
	vsep = memchr(var->ptr, '&', var->end - var->ptr);
```
이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.

<details>
<summary>이상적인 슬라이스 보기</summary>

```c
/* main/php_variables.c:335 */
SAPI_API SAPI_POST_HANDLER_FUNC(php_std_post_handler) {
    zval *arr = (zval *) arg;
    php_stream *s = SG(request_info).request_body;
    post_var_data_t post_data;

    if (s && SUCCESS == php_stream_rewind(s)) {
        memset(&post_data, 0, sizeof(post_data));

        while (!php_stream_eof(s)) {
            char buf[SAPI_POST_HANDLER_BUFSIZ] = {0};
            size_t len = php_stream_read(s, buf, SAPI_POST_HANDLER_BUFSIZ);

            if (len && len != (size_t) -1) {
                smart_str_appendl(&post_data.str, buf, len);

                if (SUCCESS != add_post_vars(arr, &post_data, 0 TSRMLS_CC)) {
                    if (post_data.str.c) {
                        efree(post_data.str.c);
                    }
                    return;
                }
            }

            if (len != SAPI_POST_HANDLER_BUFSIZ) {
                break;
            }
        }

        add_post_vars(arr, &post_data, 1 TSRMLS_CC);
        if (post_data.str.c) {
            efree(post_data.str.c);
        }
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

##### 템플릿: 비정형적 Sink
SARD의 strcpy 같은 명백한 위험 함수와 달리, CVE의 Sink는 평소에 안전한 memchr 함수입니다. 분석기는 단순히 함수 호출을 넘어, '반복문 내에서 비정상적으로 사용되는 패턴' 자체를 이해해야만 자원 고갈(DoS) 취약점으로 인지할 수 있습니다.

##### 템플릿: 상태 기반 버그
SARD는 보통 단일 행위로 문제가 발생하지만, CVE는 여러 번의 루프를 거치며 데이터 구조체의 상태가 계속 변하고 누적되어야 버그가 발생합니다. 분석기는 이처럼 시간에 따른 상태 변화를 추적해야 하는 어려움이 있습니다.

##### 템플릿: 복잡한 함수 간 루프 구조
이 CVE는 외부 함수의 루프가 내부 함수의 논리적 버그를 반복적으로 트리거하는 구조입니다. 각 함수를 독립적으로 분석해서는 찾을 수 없고, 여러 함수에 걸친 루프의 상호작용까지 분석해야 하므로 탐지 난이도가 매우 높습니다.

#### CVE-2019-12973
OpenJPEG의 이미지 변환 기능에서, 조작된 BMP 파일의 너비(width)와 높이(height) 값으로 인해 JPEG2000 인코딩 과정 중 비정상적으로 큰 반복문을 수행하게 되어 CPU 자원을 고갈시키는 서비스 거부(DoS) 취약점

1.  사용자가 OpenJPEG의 이미지 변환 유틸리티(`convertbmp.c`)를 사용하여 특수하게 조작된 BMP 이미지 파일을 JPEG2000 형식으로 변환을 시도합니다.
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

이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.

<details>
<summary>이상적인 슬라이스 보기</summary>

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
                if (! opj_alloc_tile_component_data(l_tilec)) {
                    opj_event_msg(p_manager, EVT_ERROR, "Error allocating tile component data.");
                    if (l_current_data) {
                        opj_free(l_current_data);
                    }
                    return OPJ_FALSE;
                }
            }
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
                opj_event_msg(p_manager, EVT_ERROR,
                              "Size mismatch between tile data and sent data.");
                opj_free(l_current_data);
                return OPJ_FALSE;
            }
        }

        if (! opj_j2k_post_write_tile(p_j2k, p_stream, p_manager)) {

/* src/lib/openjp2/j2k.c:11531 */
static OPJ_BOOL opj_j2k_post_write_tile(opj_j2k_t * p_j2k,
                                        opj_stream_private_t *p_stream,
                                        opj_event_mgr_t * p_manager)
{
    OPJ_UINT32 l_nb_bytes_written;
    OPJ_BYTE * l_current_data = 00;
    OPJ_UINT32 l_tile_size = 0;
    OPJ_UINT32 l_available_data;

    /* preconditions */
    assert(p_j2k->m_specific_param.m_encoder.m_encoded_tile_data);

    l_tile_size = p_j2k->m_specific_param.m_encoder.m_encoded_tile_size;
    l_available_data = l_tile_size;
    l_current_data = p_j2k->m_specific_param.m_encoder.m_encoded_tile_data;

    l_nb_bytes_written = 0;
    if (! opj_j2k_write_first_tile_part(p_j2k, l_current_data, &l_nb_bytes_written,
                                        l_available_data, p_stream, p_manager)) {

/* src/lib/openjp2/j2k.c:11773 */
static OPJ_BOOL opj_j2k_write_first_tile_part(opj_j2k_t *p_j2k,
        OPJ_BYTE * p_data,
        OPJ_UINT32 * p_data_written,
        OPJ_UINT32 p_total_data_size,
        opj_stream_private_t *p_stream,
        struct opj_event_mgr * p_manager)
{
    OPJ_UINT32 l_nb_bytes_written = 0;
    OPJ_UINT32 l_current_nb_bytes_written;
    OPJ_BYTE * l_begin_data = 00;

    opj_tcd_t * l_tcd = 00;
    opj_cp_t * l_cp = 00;

    l_tcd = p_j2k->m_tcd;
    l_cp = &(p_j2k->m_cp);

    l_tcd->cur_pino = 0;

    /*Get number of tile parts*/
    p_j2k->m_specific_param.m_encoder.m_current_poc_tile_part_number = 0;

    /* INDEX >> */
    /* << INDEX */

    l_current_nb_bytes_written = 0;
    l_begin_data = p_data;
    if (! opj_j2k_write_sot(p_j2k, p_data, p_total_data_size,
                            &l_current_nb_bytes_written, p_stream,
                            p_manager)) {
        return OPJ_FALSE;
    }

    l_nb_bytes_written += l_current_nb_bytes_written;
    p_data += l_current_nb_bytes_written;
    p_total_data_size -= l_current_nb_bytes_written;

    if (!OPJ_IS_CINEMA(l_cp->rsiz)) {
        if (l_cp->tcps[p_j2k->m_current_tile_number].numpocs) {
            l_current_nb_bytes_written = 0;
            opj_j2k_write_poc_in_memory(p_j2k, p_data, &l_current_nb_bytes_written,
                                        p_manager);
            l_nb_bytes_written += l_current_nb_bytes_written;
            p_data += l_current_nb_bytes_written;
            p_total_data_size -= l_current_nb_bytes_written;
        }
    }

    l_current_nb_bytes_written = 0;
    if (! opj_j2k_write_sod(p_j2k, l_tcd, p_data, &l_current_nb_bytes_written,
                            p_total_data_size, p_stream, p_manager)) {

/* src/lib/openjp2/j2k.c:4691 */
static OPJ_BOOL opj_j2k_write_sod(opj_j2k_t *p_j2k,
                                  opj_tcd_t * p_tile_coder,
                                  OPJ_BYTE * p_data,
                                  OPJ_UINT32 * p_data_written,
                                  OPJ_UINT32 p_total_data_size,
                                  const opj_stream_private_t *p_stream,
                                  opj_event_mgr_t * p_manager
                                 )
{
    opj_codestream_info_t *l_cstr_info = 00;
    OPJ_UINT32 l_remaining_data;

    /* preconditions */
    assert(p_j2k != 00);
    assert(p_manager != 00);
    assert(p_stream != 00);

    OPJ_UNUSED(p_stream);

    if (p_total_data_size < 4) {

    opj_write_bytes(p_data, J2K_MS_SOD,
                    2);                                 /* SOD */
    p_data += 2;

    /* make room for the EOF marker */
    l_remaining_data =  p_total_data_size - 4;

    /* update tile coder */
    p_tile_coder->tp_num =
        p_j2k->m_specific_param.m_encoder.m_current_poc_tile_part_number ;
    p_tile_coder->cur_tp_num =
        p_j2k->m_specific_param.m_encoder.m_current_tile_part_number;

    if (p_j2k->m_specific_param.m_encoder.m_current_tile_part_number == 0) {
        p_tile_coder->tcd_image->tiles->packno = 0;
#ifdef deadcode
        if (l_cstr_info) {
            l_cstr_info->packno = 0;
        }
#endif
    }

    *p_data_written = 0;

    if (! opj_tcd_encode_tile(p_tile_coder, p_j2k->m_current_tile_number, p_data,
                              p_data_written, l_remaining_data, l_cstr_info,
                              p_manager))

/* src/lib/openjp2/tcd.c:1414 */
OPJ_BOOL opj_tcd_encode_tile(opj_tcd_t *p_tcd,
                             OPJ_UINT32 p_tile_no,
                             OPJ_BYTE *p_dest,
                             OPJ_UINT32 * p_data_written,
                             OPJ_UINT32 p_max_length,
                             opj_codestream_info_t *p_cstr_info,
                             opj_event_mgr_t *p_manager)
{

    if (p_tcd->cur_tp_num == 0) {

        p_tcd->tcd_tileno = p_tile_no;
        p_tcd->tcp = &p_tcd->cp->tcps[p_tile_no];

        /* INDEX >> "Precinct_nb_X et Precinct_nb_Y" */
        if (p_cstr_info)  {
            OPJ_UINT32 l_num_packs = 0;
            OPJ_UINT32 i;
            opj_tcd_tilecomp_t *l_tilec_idx =
                &p_tcd->tcd_image->tiles->comps[0];        /* based on component 0 */
            opj_tccp_t *l_tccp = p_tcd->tcp->tccps; /* based on component 0 */

            for (i = 0; i < l_tilec_idx->numresolutions; i++) {
                opj_tcd_resolution_t *l_res_idx = &l_tilec_idx->resolutions[i];

                p_cstr_info->tile[p_tile_no].pw[i] = (int)l_res_idx->pw;
                p_cstr_info->tile[p_tile_no].ph[i] = (int)l_res_idx->ph;

                l_num_packs += l_res_idx->pw * l_res_idx->ph;
                p_cstr_info->tile[p_tile_no].pdx[i] = (int)l_tccp->prcw[i];
                p_cstr_info->tile[p_tile_no].pdy[i] = (int)l_tccp->prch[i];
            }
            p_cstr_info->tile[p_tile_no].packet = (opj_packet_info_t*) opj_calloc((
                    OPJ_SIZE_T)p_cstr_info->numcomps * (OPJ_SIZE_T)p_cstr_info->numlayers *
                                                  l_num_packs,
                                                  sizeof(opj_packet_info_t));
            if (!p_cstr_info->tile[p_tile_no].packet) {
        }
        /* << INDEX */

        /* FIXME _ProfStart(PGROUP_DC_SHIFT); */
        /*---------------TILE-------------------*/
        if (! opj_tcd_dc_level_shift_encode(p_tcd)) {
        /* FIXME _ProfStop(PGROUP_DC_SHIFT); */

        /* FIXME _ProfStart(PGROUP_MCT); */
        if (! opj_tcd_mct_encode(p_tcd)) {
        /* FIXME _ProfStop(PGROUP_MCT); */

        /* FIXME _ProfStart(PGROUP_DWT); */
        if (! opj_tcd_dwt_encode(p_tcd)) {
        /* FIXME  _ProfStop(PGROUP_DWT); */

        /* FIXME  _ProfStart(PGROUP_T1); */
        if (! opj_tcd_t1_encode(p_tcd)) {

/* src/lib/openjp2/tcd.c:2511 */
static OPJ_BOOL opj_tcd_t1_encode(opj_tcd_t *p_tcd)
{
    opj_t1_t * l_t1;
    const OPJ_FLOAT64 * l_mct_norms;
    OPJ_UINT32 l_mct_numcomps = 0U;
    opj_tcp_t * l_tcp = p_tcd->tcp;

    l_t1 = opj_t1_create(OPJ_TRUE);
    if (l_t1 == 00) {
        return OPJ_FALSE;
    }

    if (l_tcp->mct == 1) {
        l_mct_numcomps = 3U;
        /* irreversible encoding */
        if (l_tcp->tccps->qmfbid == 0) {
            l_mct_norms = opj_mct_get_mct_norms_real();
        } else {
            l_mct_norms = opj_mct_get_mct_norms();
        }
    } else {
        l_mct_numcomps = p_tcd->image->numcomps;
        l_mct_norms = (const OPJ_FLOAT64 *)(l_tcp->mct_norms);
    }

    if (! opj_t1_encode_cblks(l_t1, p_tcd->tcd_image->tiles, l_tcp, l_mct_norms,
                              l_mct_numcomps)) {

/* src/lib/openjp2/t1.c:2137 */
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
</details>


#### CVE-2018-20784
작업 중
OpenJPEG의 이미지 변환 기능에서, 조작된 BMP 파일의 너비(width)와 높이(height) 값으로 인해 JPEG2000 인코딩 과정 중 비정상적으로 큰 반복문을 수행하게 되어 CPU 자원을 고갈시키는 서비스 거부(DoS) 취약점

1. 
2. 
3. 
4. 
5. 

이 CVE 취약점을 유발하는 코드(sink:src/lib/openjp2/t1.c:2137)는 아래와 같다.

```c
샘플 코드
```

이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.

<details>
<summary>이상적인 슬라이스 보기</summary>

```c

```
</details>

#### CVE-2019-17351
작업 중
OpenJPEG의 이미지 변환 기능에서, 조작된 BMP 파일의 너비(width)와 높이(height) 값으로 인해 JPEG2000 인코딩 과정 중 비정상적으로 큰 반복문을 수행하게 되어 CPU 자원을 고갈시키는 서비스 거부(DoS) 취약점

1. 
2. 
3. 
4. 
5. 

이 CVE 취약점을 유발하는 코드(sink:src/lib/openjp2/t1.c:2137)는 아래와 같다.

```c
샘플 코드
```

이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.

<details>
<summary>이상적인 슬라이스 보기</summary>

```c

```
</details>


### CWE-78: OS Command Injection
#### CVE-2017-15108
작업 중
OpenJPEG의 이미지 변환 기능에서, 조작된 BMP 파일의 너비(width)와 높이(height) 값으로 인해 JPEG2000 인코딩 과정 중 비정상적으로 큰 반복문을 수행하게 되어 CPU 자원을 고갈시키는 서비스 거부(DoS) 취약점

1. 
2. 
3. 
4. 
5. 

이 CVE 취약점을 유발하는 코드(sink:src/lib/openjp2/t1.c:2137)는 아래와 같다.

```c
샘플 코드
```

이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.

<details>
<summary>이상적인 슬라이스 보기</summary>

```c

```
</details>

#### CVE-2017-15924
작업 중
OpenJPEG의 이미지 변환 기능에서, 조작된 BMP 파일의 너비(width)와 높이(height) 값으로 인해 JPEG2000 인코딩 과정 중 비정상적으로 큰 반복문을 수행하게 되어 CPU 자원을 고갈시키는 서비스 거부(DoS) 취약점

1. 
2. 
3. 
4. 
5. 

이 CVE 취약점을 유발하는 코드(sink:src/lib/openjp2/t1.c:2137)는 아래와 같다.

```c
샘플 코드
```

이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.

<details>
<summary>이상적인 슬라이스 보기</summary>

```c

```
</details>

#### CVE-2018-6791
작업 중
OpenJPEG의 이미지 변환 기능에서, 조작된 BMP 파일의 너비(width)와 높이(height) 값으로 인해 JPEG2000 인코딩 과정 중 비정상적으로 큰 반복문을 수행하게 되어 CPU 자원을 고갈시키는 서비스 거부(DoS) 취약점

1. 
2. 
3. 
4. 
5. 

이 CVE 취약점을 유발하는 코드(sink:src/lib/openjp2/t1.c:2137)는 아래와 같다.

```c
샘플 코드
```

이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.

<details>
<summary>이상적인 슬라이스 보기</summary>

```c

```
</details>

#### CVE-2018-16863
작업 중
OpenJPEG의 이미지 변환 기능에서, 조작된 BMP 파일의 너비(width)와 높이(height) 값으로 인해 JPEG2000 인코딩 과정 중 비정상적으로 큰 반복문을 수행하게 되어 CPU 자원을 고갈시키는 서비스 거부(DoS) 취약점

1. 
2. 
3. 
4. 
5. 

이 CVE 취약점을 유발하는 코드(sink:src/lib/openjp2/t1.c:2137)는 아래와 같다.

```c
샘플 코드
```

이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.

<details>
<summary>이상적인 슬라이스 보기</summary>

```c

```
</details>

#### CVE-2019-13638~
작업 중
OpenJPEG의 이미지 변환 기능에서, 조작된 BMP 파일의 너비(width)와 높이(height) 값으로 인해 JPEG2000 인코딩 과정 중 비정상적으로 큰 반복문을 수행하게 되어 CPU 자원을 고갈시키는 서비스 거부(DoS) 취약점

1. 
2. 
3. 
4. 
5. 

이 CVE 취약점을 유발하는 코드(sink:src/lib/openjp2/t1.c:2137)는 아래와 같다.

```c
샘플 코드
```

이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.

<details>
<summary>이상적인 슬라이스 보기</summary>

```c

```
</details>

#### CVE-2019-16718~
작업 중
OpenJPEG의 이미지 변환 기능에서, 조작된 BMP 파일의 너비(width)와 높이(height) 값으로 인해 JPEG2000 인코딩 과정 중 비정상적으로 큰 반복문을 수행하게 되어 CPU 자원을 고갈시키는 서비스 거부(DoS) 취약점

1. 
2. 
3. 
4. 
5. 

이 CVE 취약점을 유발하는 코드(sink:src/lib/openjp2/t1.c:2137)는 아래와 같다.

```c
샘플 코드
```

이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.

<details>
<summary>이상적인 슬라이스 보기</summary>

```c

```
</details>




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