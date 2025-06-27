# SARD-vs-CVE
AI가 SARD는 잘 탐지하지만 CVE는 놓치는 이유를 분석하기 위해 두 데이터를 비교합니다.

## 개요                                                

## CWE-134: FSB(Format String Bug)
### CVE-2011-4930
#### 취약점 설명
분산 컴퓨팅 도구 HTCondor에서 입력받은 사용자 계정 정보를 sprintf의 포맷 문자열로 그대로 사용하면서 발생한 **포맷 스트링 취약점**
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

<details>
<summary>이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.</summary>

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

<details>
<summary><h4 style="display:inline-block">SARD는 잘 탐지하는데 이 CVE는 탐지 못했던 이유</h4></summary>

Joern이 취약점 sink인 sprintf를 노드로 인식하지 못해 슬라이스가 생성되지 않아 취약점 예측이 불가능
</details>

### CVE-2015-8617
#### 취약점 설명
php 인터프리터에서 존재하지 않는 클래스명에 대한 예외 처리 시, 해당 클래스 명을 포맷 문자열로 그대로 사용하면서 발생한 **포맷 스트링 취약점**
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

<details>
<summary>이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.</summary>

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

<details>
<summary><h4 style="display:inline-block">SARD는 잘 탐지하는데 이 CVE는 탐지 못했던 이유</h4></summary>

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
내부 시스템 로그를 외부 로그 서버로 전송하는 rsyslog에서 ZeroMQ 연결 시, 외부에서 설정된 메시지 큐 연결 정보가 그대로 포맷 문자열로 사용되어 발생한 **포맷 스트링 취약점**

1. rsyslogd가 시작될 때 외부 로그 서버 연결 정보가 저장된 설정 파일을 읽고,

	
	<details>
	<summary><strong>설정 파일 </strong></summary>
	description에 %n을 넣으면 format string bug 발생 !


    ```conf
    *.* action(type="omzmq3" sockType="PUB" action="BIND" description="tcp://*:11514" template="any_message_template")
    ```
	
	출처: https://www.rsyslog.com/quick-guide-to-omzmq3
	</details>
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
<details>
<summary>이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.</summary>

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

<details>
<summary><h4 style="display:inline-block">SARD는 잘 탐지하는데 이 CVE는 탐지 못했던 이유</h4></summary>

##### 설정 파일 파서(Parser) 분석의 한계
Ksign 슬라이서와 같은 C/C++ 코드 기반 정적 분석 도구는 .l, .y 파일과 연계된 파서의 동작을 해석하지 못하는 한계를 가집니다. 이로 인해, CVE-2017-12588과 같이 외부 설정 파일에서 시작되어 파서의 콜백 함수를 통해 C 코드로 데이터가 유입되는 유형의 취약점은 데이터 흐름의 시작점을 놓치게 되어 탐지하지 못합니다. 이는 SARD 데이터셋처럼 순수 C 코드로만 구성된 환경에서는 드러나지 않는 문제입니다.


##### 복잡한 매크로!
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
PHP가 POST 요청을 처리하는 add_post_vars 함수에서, 처리된 데이터의 위치가 올바르게 갱신되지 않아, memchr 함수가 이미 스캔한 데이터를 포함한 전체 버퍼를 반복적으로 재검색하여 CPU 자원을 고갈시키는 서비스 거부(DoS) 취약점

1. PHP 엔진이 HTTP POST 요청을 받아 php_std_post_handler 함수를 호출합니다. 이 함수는 while 루프를 돌며 POST 데이터를 청크(chunk) 단위로 읽어 post_data 버퍼에 추가합니다.
2. php_std_post_handler는 루프를 돌 때마다 add_post_vars 함수를 호출하여 버퍼에 쌓인 데이터의 변수 파싱을 시도합니다.
3. (버그 발생) 하지만 add_post_vars 함수는 호출될 때마다 처리 위치 포인터(vars->ptr)를 항상 버퍼의 맨 처음(vars->str.c)으로 초기화합니다. 이로 인해 이전에 파싱을 시도했던 부분을 기억하지 못하고, 매번 누적된 데이터 전체를 새로 파싱하게 됩니다.
4. add_post_vars 내부에서 호출되는 add_post_var 함수는 변수 구분자인 &를 찾기 위해 memchr를 사용합니다. 버그로 인해 memchr는 이전에 이미 & 문자가 없음을 확인했던 영역까지 포함하여, 점점 커지는 전체 버퍼를 처음부터 끝까지 반복적으로 스캔하게 됩니다.
5. 공격자는 & 문자 없이 매우 큰 단일 변수(예: a=AAAA...)를 전송하여 이 시나리오를 유발합니다. 버퍼가 계속 커지고(8KB, 16KB, 24KB...) memchr의 스캔 범위가 그에 따라 선형적으로 증가하면서, CPU 사용량이 100%에 도달해 서비스가 마비됩니다. 변수가 하나이므로 max_input_vars 제한은 쉽게 우회됩니다.

이 CVE 취약점을 유발하는 코드(sink:main/php_variables.c:253, memset)는 아래와 같다.
```
static zend_bool add_post_var(zval *arr, post_var_data_t *var, zend_bool eof TSRMLS_DC){
	if (var->ptr >= var->end) {
	vsep = memchr(var->ptr, '&', var->end - var->ptr);
```
<details>
<summary>이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.</summary>

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

<details>
<summary><h4 style="display:inline-block">SARD는 잘 탐지하는데 이 CVE는 탐지 못했던 이유</h4></summary>

#### 템플릿: 비정형적 Sink
SARD의 strcpy 같은 명백한 위험 함수와 달리, CVE의 Sink는 평소에 안전한 memchr 함수입니다. 분석기는 단순히 함수 호출을 넘어, '반복문 내에서 비정상적으로 사용되는 패턴' 자체를 이해해야만 자원 고갈(DoS) 취약점으로 인지할 수 있습니다.

#### 템플릿: 상태 기반 버그
SARD는 보통 단일 행위로 문제가 발생하지만, CVE는 여러 번의 루프를 거치며 데이터 구조체의 상태가 계속 변하고 누적되어야 버그가 발생합니다. 분석기는 이처럼 시간에 따른 상태 변화를 추적해야 하는 어려움이 있습니다.

#### 템플릿: 복잡한 함수 간 루프 구조
이 CVE는 외부 함수의 루프가 내부 함수의 논리적 버그를 반복적으로 트리거하는 구조입니다. 각 함수를 독립적으로 분석해서는 찾을 수 없고, 여러 함수에 걸친 루프의 상호작용까지 분석해야 하므로 탐지 난이도가 매우 높습니다.
</details>

### CVE-2019-12973
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

<details>
<summary>이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.</summary>

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


### CVE-2018-20784
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

<details>
<summary>이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.</summary>

```c

```
</details>

### CVE-2019-17351
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

<details>
<summary>이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.</summary>

```c

```
</details>


## CWE-78: OS Command Injection
### CVE-2017-15108
가상 머신 게스트 에이전트인 `spice-vdagent`에서, 파일 전송 완료 후 저장 디렉터리를 여는 과정 중 전달받은 경로를 검증하지 않고 쉘 명령으로 만들어 실행하여, 공격자가 임의의 명령을 주입할 수 있는 OS Command Injection 취약점

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
<summary>이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.</summary>

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
Shadowsocks-libev의 `ss-manager`에서, UDP를 통해 수신한 서버 추가 요청을 부적절하게 처리하여, 공격자가 쉘 메타문자를 주입해 임의의 명령을 실행할 수 있는 OS Command Injection 취약점

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
<summary>이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.</summary>

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
KDE Plasma Workspace의 장치 관리 기능에서, `.desktop` 파일에 정의된 실행 명령의 매크로를 확장할 때 USB 드라이브의 볼륨 레이블과 같은 외부 값을 검증하지 않아, 조작된 장치를 연결 시 임의의 명령이 실행되는 OS Command Injection 취약점

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
<summary>이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.</summary>

```c
/* userDefinedServices는 KDesktopFileActions의 메소드인데 이는 외부 라이브러리에 있는 클래스이고, 파일에서 불러오는 것! 

`random.desktop` 파일 예시
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
Ghostscript의 PostScript 인터프리터에서, 파일 출력 경로에 `%pipe%` 장치를 지정할 때 파일 경로 부분을 쉘 명령으로 사용하여, 조작된 PostScript 문서를 통해 임의의 명령을 실행할 수 있는 OS Command Injection 취약점

1.  공격자가 Ghostscript가 처리할 PostScript 문서 내에서, 출력 파일 경로(`OutputFile`)를 `%pipe%` IODevice를 사용하도록 설정하고, 파이프를 통해 실행할 명령어(예: `id`)를 파일명 부분에 포함시킵니다. (예: `%pipe%id`)

2.  출력 장치가 파일을 열기 위해 `gx_device_open_output_file` 함수를 호출하면, 이 함수는 `%pipe%id` 와 같은 출력 경로 문자열을 파싱하기 시작합니다.

3.  `gs_findiodevice` 함수는 문자열 앞부분의 `%pipe%`를 인식하고, 이에 해당하는 `gs_iodev_pipe` 장치 핸들러를 찾아 반환합니다. 이 핸들러는 `pipe_fopen` 함수를 파일 열기 처리기(함수 포인터)로 가지고 있습니다.

4.  **(버그 발생)** `gx_device_open_output_file`은 찾아낸 장치 핸들러의 함수 포인터 `gp_fopen`을 호출합니다. 이 호출은 `pipe_fopen`으로 연결되며, 이때 `%pipe%` 뒷부분의 문자열(`id`)이 검증 없이 `fname` 인자로 그대로 전달됩니다.

5.  최종적으로 `pipe_fopen` 함수는 전달받은 `fname` 문자열을 `popen()` 함수(Sink)에 인자로 넘겨 실행합니다. 이로 인해 공격자가 파일명으로 지정한 `id` 명령어가 시스템에서 실행됩니다.
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
<summary>이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.</summary>

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

/* str이 OutputFile인거고 gx_io_device *iodev = libctx->io_device_table[i]; 에서 적절한 device를 찾은 다음에 if (dname && strlen(dname) == len + 1 && !memcmp(str, dname, len))에서 device의 첫번째 인자 "%PIPE%"와 str 값을 비교 */
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
GNU `patch` 유틸리티에서, ed 스크립트 형식의 패치를 처리할 때 출력 파일명(`-o` 옵션)을 검증 없이 쉘 명령의 일부로 사용하여, 조작된 파일명을 통해 임의의 명령을 실행할 수 있는 OS Command Injection 취약점

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
<summary>이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.</summary>

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
radare2의 명령어 처리기에서, 악의적으로 조작된 심볼 이름을 포함한 바이너리 파일 분석 시, 심볼 정보를 출력하는 특정 명령어(`is*`)의 결과를 다시 명령으로 해석하는 과정에서 백틱(\`)으로 감싸인 심볼 이름이 쉘 명령으로 실행되는 OS Command Injection 취약점

1.  공격자가 심볼 이름에 쉘 메타문자(예: `` `!id` ``)가 포함된 악성 바이너리 파일을 준비하고, 사용자가 radare2에서 이 파일을 연 뒤 심볼 정보를 출력하는 명령어(예: `.is*`)를 실행합니다.

2.  `bin_symbols` 함수는 바이너리에서 악성 심볼 이름을 읽어(Source), 이를 포함한 radare2 플래그 설정 명령어(예: `f sym.imp.\`!id\``)를 문자열로 생성하여 출력합니다.

3.  명령어 맨 앞의 `.`(점)으로 인해, `cmd_interpret` 함수는 2단계에서 출력된 `"f sym.imp.\`!id\`"` 문자열을 새로운 명령으로 받아들여 `r_core_cmd0`를 통해 다시 radare2 명령어 처리기에 전달합니다.

4.  **(버그 발생)** 명령어 처리 중 `r_core_cmd_subst_i` 함수는 백틱(`` ` ``)으로 감싸인 부분을 발견하고, 그 내용이 `!`로 시작하는 것을 확인합니다. 이는 '내부의 `!id`를 시스템 명령으로 실행하고 그 결과로 대체하라'는 의미로 해석됩니다.

5.  `!` 문자로 인해 `id` 문자열은 `cmd_system` 콜백에 전달되고, 최종적으로 `r_sandbox_system` 함수를 통해 `system("id")` (Sink)가 호출되어 공격자가 심볼 이름에 숨겨둔 임의의 명령이 실행됩니다.

이 CVE 취약점을 유발하는 코드(sink:libr/core/cmd.c:3017)는 아래와 같다.

```c
/* libr/core/cmd.c:3017 */
// *cmd = "f sym.imp.`!sleep 999` 16 0x0"
static int r_core_cmd_subst_i(RCore *core, char *cmd, char *colon, bool *tmpseek) { 
	if (!cmd) {
	cmd = r_str_trim_head_tail (cmd);
next2:
	ptr = strchr (cmd, '`'); // *(ptr) = '`!sleep 999` 16 0x0'
	if (ptr) {
		if (ptr > cmd) {
		bool empty = false;
		if (empty) {
		} else {
			*ptr = '\0';
			if (ptr[1] == '!') { 
				str = r_core_cmd_str_pipe (core, ptr + 1); 
				// *(ptr + 1) = '!sleep 999` 16 0x0'
				// !로 시작하면 내부적으로 bash command로서 실행.
```

<details>
<summary>이 코드에서 Ksign 슬라이서 도구가 추출했어야 하는 슬라이스를 직접 작성해보면 다음과 같다.</summary>

```c
/* cbin.c:2043 */
static int bin_symbols(RCore *r, int mode, ut64 laddr, int va, ut64 at, const char *name, bool exponly, const char *args) {
	RBinInfo *info = r_bin_get_info (r->bin);
	RList *entries = r_bin_get_entries (r->bin);
	RBinSymbol *symbol;
	RBinAddr *entry;
	RListIter *iter;
	bool firstexp = true;
	bool printHere = false;
	int i = 0, lastfs = 's';
	bool bin_demangle = r_config_get_i (r->config, "bin.demangle");
	if (!info) {
		return 0;
	}

	if (args && *args == '.') {
		printHere = true;
	}

	bool is_arm = info && info->arch && !strncmp (info->arch, "arm", 3);
	const char *lang = bin_demangle ? r_config_get (r->config, "bin.lang") : NULL;

	RList *symbols = r_bin_get_symbols (r->bin);

	/* cbin.c:2073 */
	size_t count = 0;
	r_list_foreach (symbols, iter, symbol) {
		if (!symbol->name) {
			continue;
		}
		char *r_symbol_name = r_str_escape_utf8 (symbol->name, false, true);

	/* cbin.c:2216 */
	const char *name = sn.demname? sn.demname: r_symbol_name;
	if (!name) {
		goto next;
	}
	if (!strncmp (name, "imp.", 4)) {
		if (lastfs != 'i') {
			r_cons_printf ("fs imports\n");
		}
		lastfs = 'i';
	} else {
		if (lastfs != 's') {
			const char *fs = exponly? "exports": "symbols";
			r_cons_printf ("fs %s\n", fs);
		}
		lastfs = 's';
	}
	if (r->bin->prefix || *name) { // we don't want unnamed symbol flags
		char *flagname = construct_symbol_flagname ("sym", name, MAXFLAG_LEN_DEFAULT);
		if (!flagname) {
			goto next;
		}
		r_cons_printf ("\"f %s%s%s %u 0x%08" PFMT64x "\"\n",
			r->bin->prefix ? r->bin->prefix : "", r->bin->prefix ? "." : "",
			flagname, symbol->size, addr);

/* libr/core/cbin.c:3811 */
R_API int r_core_bin_info(RCore *core, int action, int mode, int va, RCoreBinFilter *filter, const char *chksum) {
	int ret = true;
	const char *name = NULL;
	ut64 at = 0, loadaddr = r_bin_get_laddr (core->bin);
	if (filter && filter->offset) {
	if (filter && filter->name) {

	// use our internal values for va
	va = va ? VA_TRUE : VA_FALSE;
	if ((action & R_CORE_BIN_ACC_STRINGS)) {
	if ((action & R_CORE_BIN_ACC_RAW_STRINGS)) {
	if ((action & R_CORE_BIN_ACC_INFO)) {
	if ((action & R_CORE_BIN_ACC_MAIN)) {
	if ((action & R_CORE_BIN_ACC_DWARF)) {
	if ((action & R_CORE_BIN_ACC_PDB)) {
	if ((action & R_CORE_BIN_ACC_SOURCE)) {
	if ((action & R_CORE_BIN_ACC_ENTRIES)) {
	if ((action & R_CORE_BIN_ACC_INITFINI)) {
	if ((action & R_CORE_BIN_ACC_SECTIONS)) {
	if ((action & R_CORE_BIN_ACC_SEGMENTS)) {
	if (r_config_get_i (core->config, "bin.relocs")) {
		if ((action & R_CORE_BIN_ACC_RELOCS)) {
	}
	if ((action & R_CORE_BIN_ACC_LIBS)) {
	if ((action & R_CORE_BIN_ACC_IMPORTS)) { // 5s
	if ((action & R_CORE_BIN_ACC_EXPORTS)) {
		ret &= bin_symbols (core, mode, loadaddr, va, at, name, true, chksum);
	}
	if ((action & R_CORE_BIN_ACC_SYMBOLS)) { // 6s
		ret &= bin_symbols (core, mode, loadaddr, va, at, name, false, chksum);

/* libr/core/cmd_info.c:571 */ 
static int cmd_info(void *data, const char *input) {
	RCore *core = (RCore *) data;
	bool newline = r_cons_is_interactive ();
	int fd = r_io_fd_get_current (core->io);
	RIODesc *desc = r_io_desc_get (core->io, fd);
	int i, va = core->io->va || core->io->debug;
	int mode = 0; //R_MODE_SIMPLE;
	bool rdump = false;
	int is_array = 0;
	Sdb *db;

	for (i = 0; input[i] && input[i] != ' '; i++)
		;
	if (i > 0) {
		switch (input[i - 1]) {
		case '*': mode = R_MODE_RADARE; break;
		case 'j': mode = R_MODE_JSON; break;
		case 'q': mode = R_MODE_SIMPLE; break;
		}
	}
	if (mode == R_MODE_JSON) {
		int suffix_shift = 0;
		if (!strncmp (input, "SS", 2) || !strncmp (input, "ee", 2)
			|| !strncmp (input, "zz", 2)) {
			suffix_shift = 1;
		}
		if (strlen (input + 1 + suffix_shift) > 1) {
			is_array = 1;
		}
	}
	if (is_array) {
		r_cons_printf ("{");
	}
	if (!*input) {
		cmd_info_bin (core, va, mode);
	}
	/* i* is an alias for iI* */
	if (!strcmp (input, "*")) {
		input = "I*";
	}
	char *question = strchr (input, '?');
	const char *space = strchr (input, ' ');
	if (!space) {
		space = question + 1;
	}
	if (question < space && question > input) {
	while (*input) {
		switch (*input) {
		case 'o': // "io"
		{
			if (!desc) {
				eprintf ("Core file not open\n");
				return 0;
			}
			const char *fn = input[1] == ' '? input + 2: desc->name;
			ut64 baddr = r_config_get_i (core->config, "bin.baddr");
			r_core_bin_load (core, fn, baddr);
		}
		break;
			#define RBININFO(n,x,y,z)\
				if (is_array) {\
					if (is_array == 1) { is_array++;\
					} else { r_cons_printf (",");}\
					r_cons_printf ("\"%s\":",n);\
				}\
				if (z) { playMsg (core, n, z);}\
				r_core_bin_info (core, x, mode, va, NULL, y);

/* libr/core/cmd_info.c:793 */ 
static int cmd_info(void *data, const char *input) {
	RCore *core = (RCore *) data;
	bool newline = r_cons_is_interactive ();
	int fd = r_io_fd_get_current (core->io);
	RIODesc *desc = r_io_desc_get (core->io, fd);
	int i, va = core->io->va || core->io->debug;
	int mode = 0; //R_MODE_SIMPLE;
	bool rdump = false;
	int is_array = 0;
	Sdb *db;

	for (i = 0; input[i] && input[i] != ' '; i++)
		;
	if (i > 0) {
		switch (input[i - 1]) {
		case '*': mode = R_MODE_RADARE; break;
		case 'j': mode = R_MODE_JSON; break;
		case 'q': mode = R_MODE_SIMPLE; break;
		}
	}
	if (mode == R_MODE_JSON) {
		int suffix_shift = 0;
		if (!strncmp (input, "SS", 2) || !strncmp (input, "ee", 2)
			|| !strncmp (input, "zz", 2)) {
			suffix_shift = 1;
		}
		if (strlen (input + 1 + suffix_shift) > 1) {
			is_array = 1;
		}
	}
	if (is_array) {
		r_cons_printf ("{");
	}
	if (!*input) {
		cmd_info_bin (core, va, mode);
	}
	/* i* is an alias for iI* */
	if (!strcmp (input, "*")) {
		input = "I*";
	}
	char *question = strchr (input, '?');
	const char *space = strchr (input, ' ');
	if (!space) {
		space = question + 1;
	}
	if (question < space && question > input) {
	while (*input) {
		switch (*input) { // *input = "s*"
		case 's': { // "is"
			RBinObject *obj = r_bin_cur_object (core->bin);
			// Case for isj.
			if (input[1] == 'j' && input[2] == '.') {
				mode = R_MODE_JSON;
				RBININFO ("symbols", R_CORE_BIN_ACC_SYMBOLS, input + 2, (obj && obj->symbols)? r_list_length (obj->symbols): 0);
			} else if (input[1] == 'q' && input[2] == 'q') {
				mode = R_MODE_SIMPLEST;
				RBININFO ("symbols", R_CORE_BIN_ACC_SYMBOLS, input + 1, (obj && obj->symbols)? r_list_length (obj->symbols): 0);
			} else if (input[1] == 'q' && input[2] == '.') {
				mode = R_MODE_SIMPLE;
				RBININFO ("symbols", R_CORE_BIN_ACC_SYMBOLS, input + 2, 0);
			} else {
				RBININFO ("symbols", R_CORE_BIN_ACC_SYMBOLS, input + 1, (obj && obj->symbols)? r_list_length (obj->symbols): 0);

/* libr/core/cmd.c:4734 */
R_API void r_core_cmd_init(RCore *core) {
	struct {
		const char *cmd;
		const char *description;
		int (*callback)(void *data, const char *input)
		int (*cb)(void *data, const char *input)
	} cmds[] = {
		{"info",     "get file info", cmd_info, cmd_info_init},
	...
		for (i = 0; i < R_ARRAY_SIZE (cmds); i++) {
		r_cmd_add (core->rcmd, cmds[i].cmd, cmds[i].description, cmds[i].cb);
	}

/* libr/core/cmd_api.c:244 */
R_API int r_cmd_call(RCmd *cmd, const char *input) {
	struct r_cmd_item_t *c;
	int ret = -1;
	RListIter *iter;
	RCorePlugin *cp;
	r_return_val_if_fail (cmd && input, -1);
	if (!*input) {
	} else {
		char *nstr = NULL;
		const char *ji = r_cmd_alias_get (cmd, input, 1);
		if (ji) {
		}
		r_list_foreach (cmd->plist, iter, cp) {
		}
		if (!*input) {
		}
		c = cmd->cmds[((ut8)input[0]) & 0xff];
		if (c && c->callback) {
			const char *inp = (*input)? input + 1: ""; // *input = "is*", *inp = "s*"
			ret = c->callback (cmd->data, inp);

/* libr/core/cmd.c:3538 */
static int r_core_cmd_subst_i(RCore *core, char *cmd, char *colon, bool *tmpseek) {
	RList *tmpenvs = r_list_newf (tmpenvs_free);
	const char *quotestr = "`";
	const char *tick = NULL;
	char *ptr, *ptr2, *str;
	char *arroba = NULL;
	char *grep = NULL;
	RIODesc *tmpdesc = NULL;
	int pamode = !core->io->va;
	int i, ret = 0, pipefd;
	bool usemyblock = false;
	int scr_html = -1;
	int scr_color = -1;
	bool eos = false;
	bool haveQuote = false;
	bool oldfixedarch = core->fixedarch;
	bool oldfixedbits = core->fixedbits;
	bool cmd_tmpseek = false;
	ut64 tmpbsz = core->blocksize;
	int cmd_ignbithints = -1;

	if (!cmd) {
		r_list_free (tmpenvs);
		return 0;
	}
	cmd = r_str_trim_head_tail (cmd);
	...
	
fuji:
	rc = cmd? r_cmd_call (core->rcmd, r_str_trim_head (cmd)): false;

/* libr/core/cmd.c:2418 */
static int r_core_cmd_subst(RCore *core, char *cmd) {
	ut64 rep = strtoull (cmd, NULL, 10);
	int ret = 0, orep;
	char *cmt, *colon = NULL, *icmd = NULL;
	bool tmpseek = false;
	bool original_tmpseek = core->tmpseek;

	if (r_str_startswith (cmd, "GET /cmd/")) {
		memmove (cmd, cmd + 9, strlen (cmd + 9) + 1);
		char *http = strstr (cmd, "HTTP");
		if (http) {
			*http = 0;
			http--;
			if (*http == ' ') {
				*http = 0;
			}
		}
		r_cons_printf ("HTTP/1.0 %d %s\r\n%s"
				"Connection: close\r\nContent-Length: %d\r\n\r\n",
				200, "OK", "", -1);
		return r_core_cmd0 (core, cmd);
	}

	/* must store a local orig_offset because there can be
	* nested call of this function */
	ut64 orig_offset = core->offset;
	icmd = strdup (cmd);

	if (core->max_cmd_depth - core->cons->context->cmd_depth == 1) {
		core->prompt_offset = core->offset;
	}
	cmd = r_str_trim_head_tail (icmd);
	if (*cmd != '"') {
	} else {
		colon = NULL;
	}
	if (rep > 0) {
		while (IS_DIGIT (*cmd)) {
			cmd++;
		}
		// do not repeat null cmd
		if (!*cmd) {
	}
	if (rep < 1) {
		rep = 1;
	}
	// XXX if output is a pipe then we don't want to be interactive
	if (rep > 1 && r_sandbox_enable (0)) {
	} else {
	}
	// TODO: store in core->cmdtimes to speedup ?
	const char *cmdrep = core->cmdtimes ? core->cmdtimes: "";
	orep = rep;

	r_cons_break_push (NULL, NULL);

	int ocur_enabled = core->print && core->print->cur_enabled;
	while (rep-- && *cmd) {
		if (core->print) {
			core->print->cur_enabled = false;
			if (ocur_enabled && core->seltab >= 0) {
				if (core->seltab == core->curtab) {
					core->print->cur_enabled = true;
				}
			}
		}
		if (r_cons_is_breaked ()) {
		char *cr = strdup (cmdrep);
		core->break_loop = false;
		ret = r_core_cmd_subst_i (core, cmd, colon, (rep == orep - 1) ? &tmpseek : NULL);

/* libr/core/cmd.c:4373 */
R_API int r_core_cmd(RCore *core, const char *cstr, int log) {
	char *cmd, *ocmd, *ptr, *rcmd;
	int ret = false, i;

	if (core->cmdfilter) {
		const char *invalid_chars = ";|>`@";
		for (i = 0; invalid_chars[i]; i++) {
			if (strchr (cstr, invalid_chars[i])) {
		}
		if (strncmp (cstr, core->cmdfilter, strlen (core->cmdfilter))) {
	}
	if (core->cmdremote) {
		if (*cstr != '=' && *cstr != 'q' && strncmp (cstr, "!=", 2)) {
	}

	if (!cstr || (*cstr == '|' && cstr[1] != '?')) {
	if (!strncmp (cstr, "/*", 2)) {
		if (r_sandbox_enable (0)) {
		core->incomment = true;
	} else if (!strncmp (cstr, "*/", 2)) {
	if (core->incomment) {
	if (log && (*cstr && (*cstr != '.' || !strncmp (cstr, ".(", 2)))) {
		free (core->lastcmd);
		core->lastcmd = strdup (cstr);
	}

	ocmd = cmd = malloc (strlen (cstr) + 4096);
	if (!ocmd) {
	r_str_cpy (cmd, cstr);
	if (log) {
		r_line_hist_add (cstr);
	}

	if (core->cons->context->cmd_depth < 1) {
	core->cons->context->cmd_depth--;
	for (rcmd = cmd;;) {
		ptr = strchr (rcmd, '\n');
		if (ptr) {
			*ptr = '\0';
		}
		ret = r_core_cmd_subst (core, rcmd);


/* libr/core/cmd.c:4623 */
/* return: pointer to a buffer with the output of the command */
R_API char *r_core_cmd_str(RCore *core, const char *cmd) {
	const char *static_str;
	char *retstr = NULL;
	r_cons_push ();
	if (r_core_cmd (core, cmd, 0) == -1) {

// is*
/* libr/core/cmd.c:1231 */
static int cmd_interpret(void *data, const char *input) {
	char *str, *ptr, *eol, *rbuf, *filter, *inp;
	const char *host, *port, *cmd;
	RCore *core = (RCore *)data;

	switch (*input) {
	default:
		if (*input >= 0 && *input <= 9) {
			eprintf ("|ERROR| No .[0..9] to avoid infinite loops\n");
			break;
		}
		inp = strdup (input);
		filter = strchr (inp, '~');
		if (filter) {
		int tmp_html = r_cons_singleton ()->is_html;
		r_cons_singleton ()->is_html = 0;
		ptr = str = r_core_cmd_str (core, inp); // *inp = "is*"
		// *(ptr) = "f sym.imp.`!sleep 999` 16 0x0\nf sym.imp.`!sleep 999` 16 0x0\nf sym.imp.`!sleep 999` 16 0x0\n"

		r_cons_singleton ()->is_html = tmp_html;

		if (filter) {
		r_cons_break_push (NULL, NULL);
		if (ptr) {
			for (;;) {
				if (r_cons_is_breaked ()) {
					break;
				}
				eol = strchr (ptr, '\n');
				if (eol) {
					*eol = '\0';
				}
				if (*ptr) {
					// *(ptr) = "f sym.imp.`!sleep 999` 16 0x0\0"
					char *p = r_str_append (strdup (ptr), filter); 
					r_core_cmd0 (core, p);

                    
/* f sym.imp.`!sleep 999` 16 0x0 */
/* libr/core/cmd.c:4538 */
R_API int r_core_cmd0(RCore *core, const char *cmd) {
	return r_core_cmd (core, cmd, 0);

/* libr/core/cmd.c:4373 */
R_API int r_core_cmd(RCore *core, const char *cstr, int log) {
	char *cmd, *ocmd, *ptr, *rcmd;
	int ret = false, i;

	if (core->cmdfilter) {
		const char *invalid_chars = ";|>`@";
		for (i = 0; invalid_chars[i]; i++) {
			if (strchr (cstr, invalid_chars[i])) {
		}
		if (strncmp (cstr, core->cmdfilter, strlen (core->cmdfilter))) {
	}
	if (core->cmdremote) {
		if (*cstr != '=' && *cstr != 'q' && strncmp (cstr, "!=", 2)) {
	}

	if (!cstr || (*cstr == '|' && cstr[1] != '?')) {
	if (!strncmp (cstr, "/*", 2)) {
		if (r_sandbox_enable (0)) {
		}
		core->incomment = true;
	} else if (!strncmp (cstr, "*/", 2)) {
	}
	if (core->incomment) {
	}
	if (log && (*cstr && (*cstr != '.' || !strncmp (cstr, ".(", 2)))) {
		free (core->lastcmd);
		core->lastcmd = strdup (cstr);
	}

	ocmd = cmd = malloc (strlen (cstr) + 4096);
	if (!ocmd) {
	r_str_cpy (cmd, cstr);
	if (log) {

	if (core->cons->context->cmd_depth < 1) {
	core->cons->context->cmd_depth--;
	for (rcmd = cmd;;) {
		ptr = strchr (rcmd, '\n'); 
		if (ptr) {
			*ptr = '\0';
		}
		ret = r_core_cmd_subst (core, rcmd);
    
/* libr/core/cmd.c:2418 */
static int r_core_cmd_subst(RCore *core, char *cmd) {
	ut64 rep = strtoull (cmd, NULL, 10);
	int ret = 0, orep;
	char *cmt, *colon = NULL, *icmd = NULL;
	bool tmpseek = false;
	bool original_tmpseek = core->tmpseek;

	if (r_str_startswith (cmd, "GET /cmd/")) {
		memmove (cmd, cmd + 9, strlen (cmd + 9) + 1);
		char *http = strstr (cmd, "HTTP");
		if (http) {
			*http = 0;
			http--;
			if (*http == ' ') {
				*http = 0;
			}
		}
		r_cons_printf ("HTTP/1.0 %d %s\r\n%s"
				"Connection: close\r\nContent-Length: %d\r\n\r\n",
				200, "OK", "", -1);
		return r_core_cmd0 (core, cmd);
	}

	/* must store a local orig_offset because there can be
	 * nested call of this function */
	ut64 orig_offset = core->offset;
	icmd = strdup (cmd);

	if (core->max_cmd_depth - core->cons->context->cmd_depth == 1) {
		core->prompt_offset = core->offset;
	}
	cmd = r_str_trim_head_tail (icmd);
	if (*cmd != '"') {
	} else {
		colon = NULL;
	}
	if (rep > 0) {
		while (IS_DIGIT (*cmd)) {
			cmd++;
		}
		// do not repeat null cmd
		if (!*cmd) {
	}
	if (rep < 1) {
		rep = 1;
	}
	// XXX if output is a pipe then we don't want to be interactive
	if (rep > 1 && r_sandbox_enable (0)) {
	} else {
	}
	// TODO: store in core->cmdtimes to speedup ?
	const char *cmdrep = core->cmdtimes ? core->cmdtimes: "";
	orep = rep;

	r_cons_break_push (NULL, NULL);

	int ocur_enabled = core->print && core->print->cur_enabled;
	while (rep-- && *cmd) {
		if (core->print) {
			core->print->cur_enabled = false;
			if (ocur_enabled && core->seltab >= 0) {
				if (core->seltab == core->curtab) {
					core->print->cur_enabled = true;
				}
			}
		}
		if (r_cons_is_breaked ()) {
		char *cr = strdup (cmdrep);
		core->break_loop = false;
		ret = r_core_cmd_subst_i (core, cmd, colon, (rep == orep - 1) ? &tmpseek : NULL);

/* libr/core/cmd.c:3017 */
static int r_core_cmd_subst_i(RCore *core, char *cmd, char *colon, bool *tmpseek) {
	RList *tmpenvs = r_list_newf (tmpenvs_free);
	const char *quotestr = "`";
	const char *tick = NULL;
	char *ptr, *ptr2, *str;
	char *arroba = NULL;
	char *grep = NULL;
	RIODesc *tmpdesc = NULL;
	int pamode = !core->io->va;
	int i, ret = 0, pipefd;
	bool usemyblock = false;
	int scr_html = -1;
	int scr_color = -1;
	bool eos = false;
	bool haveQuote = false;
	bool oldfixedarch = core->fixedarch;
	bool oldfixedbits = core->fixedbits;
	bool cmd_tmpseek = false;
	ut64 tmpbsz = core->blocksize;
	int cmd_ignbithints = -1;

	if (!cmd) {
		r_list_free (tmpenvs);
		return 0;
	}
	cmd = r_str_trim_head_tail (cmd);
escape_redir:
next2:
	/* sub commands */
	ptr = strchr (cmd, '`'); // *(ptr) = '`!sleep 999` 16 0x0', ptr는 실행할 명령어, *(cmd) = "f sym.imp.`!sleep 999` 16 0x0"
	if (ptr) {
		if (ptr > cmd) {
		bool empty = false;
		int oneline = 1;
		if (ptr[1] == '`') {
		ptr2 = strchr (ptr + 1, '`');
		if (empty) {
			/* do nothing */
		} else if (!ptr2) {
		} else {
			int value = core->num->value;
			*ptr = '\0';
			*ptr2 = '\0';
			if (ptr[1] == '!') { 
				str = r_core_cmd_str_pipe (core, ptr + 1); 
				// *(ptr + 1) = '!sleep 999', ptr는 실행할 명령어

/* libr/core/cmd.c:4585 */
R_API char *r_core_cmd_str_pipe(RCore *core, const char *cmd) {
	char *s, *tmp = NULL;
	if (r_sandbox_enable (0)) {
		char *p = (*cmd != '"')? strchr (cmd, '|'): NULL;
		if (p) {
		}
		return r_core_cmd_str (core, cmd);
	}
	r_cons_reset ();
	r_sandbox_disable (1);
	if (r_file_mkstemp ("cmd", &tmp) != -1) {
		int pipefd = r_cons_pipe_open (tmp, 1, 0);
		if (pipefd == -1) {
		char *_cmd = strdup (cmd);
		r_core_cmd_subst (core, _cmd);

/* libr/core/cmd.c:2418 */
static int r_core_cmd_subst(RCore *core, char *cmd) {
	ut64 rep = strtoull (cmd, NULL, 10);
	int ret = 0, orep;
	char *cmt, *colon = NULL, *icmd = NULL;
	bool tmpseek = false;
	bool original_tmpseek = core->tmpseek;

	if (r_str_startswith (cmd, "GET /cmd/")) {
		memmove (cmd, cmd + 9, strlen (cmd + 9) + 1);
		char *http = strstr (cmd, "HTTP");
		if (http) {
			*http = 0;
			http--;
			if (*http == ' ') {
				*http = 0;
			}
		}
		r_cons_printf ("HTTP/1.0 %d %s\r\n%s"
				"Connection: close\r\nContent-Length: %d\r\n\r\n",
				200, "OK", "", -1);
		return r_core_cmd0 (core, cmd);
	}

	/* must store a local orig_offset because there can be
	 * nested call of this function */
	ut64 orig_offset = core->offset;
	icmd = strdup (cmd);

	if (core->max_cmd_depth - core->cons->context->cmd_depth == 1) {
		core->prompt_offset = core->offset;
	}
	cmd = r_str_trim_head_tail (icmd);
	if (*cmd != '"') {
	} else {
		colon = NULL;
	}
	if (rep > 0) {
		while (IS_DIGIT (*cmd)) {
			cmd++;
		}
		// do not repeat null cmd
		if (!*cmd) {
	}
	if (rep < 1) {
		rep = 1;
	}
	// XXX if output is a pipe then we don't want to be interactive
	if (rep > 1 && r_sandbox_enable (0)) {
	} else {
	}
	// TODO: store in core->cmdtimes to speedup ?
	const char *cmdrep = core->cmdtimes ? core->cmdtimes: "";
	orep = rep;

	r_cons_break_push (NULL, NULL);

	int ocur_enabled = core->print && core->print->cur_enabled;
	while (rep-- && *cmd) {
		if (core->print) {
			core->print->cur_enabled = false;
			if (ocur_enabled && core->seltab >= 0) {
				if (core->seltab == core->curtab) {
					core->print->cur_enabled = true;
				}
			}
		}
		if (r_cons_is_breaked ()) {
		char *cr = strdup (cmdrep);
		core->break_loop = false;
		ret = r_core_cmd_subst_i (core, cmd, colon, (rep == orep - 1) ? &tmpseek : NULL);

/* libr/core/cmd.c:3538 */
static int r_core_cmd_subst_i(RCore *core, char *cmd, char *colon, bool *tmpseek) {
	RList *tmpenvs = r_list_newf (tmpenvs_free);
	const char *quotestr = "`";
	const char *tick = NULL;
	char *ptr, *ptr2, *str;
	char *arroba = NULL;
	char *grep = NULL;
	RIODesc *tmpdesc = NULL;
	int pamode = !core->io->va;
	int i, ret = 0, pipefd;
	bool usemyblock = false;
	int scr_html = -1;
	int scr_color = -1;
	bool eos = false;
	bool haveQuote = false;
	bool oldfixedarch = core->fixedarch;
	bool oldfixedbits = core->fixedbits;
	bool cmd_tmpseek = false;
	ut64 tmpbsz = core->blocksize;
	int cmd_ignbithints = -1;

	if (!cmd) {
		r_list_free (tmpenvs);
		return 0;
	}
	cmd = r_str_trim_head_tail (cmd);
    ...
	
fuji:
	rc = cmd? r_cmd_call (core->rcmd, r_str_trim_head (cmd)): false;


/* libr/core/cmd_api.c:244 */
R_API int r_cmd_call(RCmd *cmd, const char *input) {
	struct r_cmd_item_t *c;
	int ret = -1;
	RListIter *iter;
	RCorePlugin *cp;
	r_return_val_if_fail (cmd && input, -1);
	if (!*input) {
	} else {
		char *nstr = NULL;
		const char *ji = r_cmd_alias_get (cmd, input, 1);
		if (ji) {
		}
		r_list_foreach (cmd->plist, iter, cp) {
		}
		if (!*input) {
		}
		c = cmd->cmds[((ut8)input[0]) & 0xff];
		if (c && c->callback) {
			const char *inp = (*input)? input + 1: ""; 
			// input = '!sleep 999'
			// *(input+1) = sleep 999
			ret = c->callback (cmd->data, inp);

/*
	libr/core/cmd_api.c:199
	R_API int r_cmd_add(RCmd *c, const char *cmd, const char *desc, r_cmd_callback(cb)) {
		int idx = (ut8)cmd[0];
		RCmdItem *item = c->cmds[idx];
		if (!item) {
			item = R_NEW0 (RCmdItem);
			c->cmds[idx] = item;
		}
		strncpy (item->cmd, cmd, sizeof (item->cmd)-1);
		strncpy (item->desc, desc, sizeof (item->desc)-1);
		item->callback = cb;
*/

/* libr/core/cmd.c:4734 */
R_API void r_core_cmd_init(RCore *core) {
	struct {
		const char *cmd;
		const char *description;
		int (*callback)(void *data, const char *input)
		int (*cb)(void *data, const char *input)
	} cmds[] = {
		{"!",        "run system command", cmd_system},
    ...
    	for (i = 0; i < R_ARRAY_SIZE (cmds); i++) {
		r_cmd_add (core->rcmd, cmds[i].cmd, cmds[i].description, cmds[i].cb);
	}

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


// x = 'sleep 999', x는 실행할 명령어
```
</details>


<!--
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
-->