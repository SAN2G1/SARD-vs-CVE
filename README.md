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