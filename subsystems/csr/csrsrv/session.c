/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Client/Server Runtime SubSystem
 * FILE:            subsystems/win32/csrsrv/session.c
 * PURPOSE:         CSR Server DLL Session Implementation
 * PROGRAMMERS:     Alex Ionescu (alex@relsoft.net)
 */

/* INCLUDES *******************************************************************/

#include "srv.h"

#define NDEBUG
#include <debug.h>

/* DATA ***********************************************************************/

RTL_CRITICAL_SECTION CsrNtSessionLock;
LIST_ENTRY CsrNtSessionList;

PSB_API_ROUTINE CsrServerSbApiDispatch[SbpMaxApiNumber - SbpCreateSession] =
{
    CsrSbCreateSession,
    CsrSbTerminateSession,
    CsrSbForeignSessionComplete,
    CsrSbCreateProcess
};

PCHAR CsrServerSbApiName[SbpMaxApiNumber - SbpCreateSession] =
{
    "SbCreateSession",
    "SbTerminateSession",
    "SbForeignSessionComplete",
    "SbCreateProcess"
};

/* PRIVATE FUNCTIONS **********************************************************/

/*++
 * @name CsrInitializeNtSessionList
 *
 * The CsrInitializeNtSessionList routine sets up support for CSR Sessions.
 *
 * @param None
 *
 * @return None
 *
 * @remarks None.
 *
 *--*/
NTSTATUS
NTAPI
CsrInitializeNtSessionList(VOID)
{
    /* Initialize the Session List */
    InitializeListHead(&CsrNtSessionList);

    /* Initialize the Session Lock */
    return RtlInitializeCriticalSection(&CsrNtSessionLock);
}

/*++
 * @name CsrAllocateNtSession
 *
 * The CsrAllocateNtSession routine allocates a new CSR NT Session.
 *
 * @param SessionId
 *        Session ID of the CSR NT Session to allocate.
 *
 * @return Pointer to the newly allocated CSR NT Session.
 *
 * @remarks None.
 *
 *--*/
PCSR_NT_SESSION
NTAPI
CsrAllocateNtSession(IN ULONG SessionId)
{
    PCSR_NT_SESSION NtSession;

    /* Allocate an NT Session Object */
    NtSession = RtlAllocateHeap(CsrHeap, HEAP_ZERO_MEMORY, sizeof(CSR_NT_SESSION));
    if (NtSession)
    {
        /* Setup the Session Object */
        NtSession->SessionId = SessionId;
        NtSession->ReferenceCount = 1;

        /* Insert it into the Session List */
        CsrAcquireNtSessionLock();
        InsertHeadList(&CsrNtSessionList, &NtSession->SessionLink);
        CsrReleaseNtSessionLock();
    }
    else
    {
        ASSERT(NtSession != NULL);
    }

    /* Return the Session (or NULL) */
    return NtSession;
}

/*++
 * @name CsrReferenceNtSession
 *
 * The CsrReferenceNtSession increases the reference count of a CSR NT Session.
 *
 * @param Session
 *        Pointer to the CSR NT Session to reference.
 *
 * @return None.
 *
 * @remarks None.
 *
 *--*/
VOID
NTAPI
CsrReferenceNtSession(IN PCSR_NT_SESSION Session)
{
    /* Acquire the lock */
    CsrAcquireNtSessionLock();

    /* Sanity checks */
    ASSERT(!IsListEmpty(&Session->SessionLink));
    ASSERT(Session->SessionId != 0);
    ASSERT(Session->ReferenceCount != 0);

    /* Increase the reference count */
    Session->ReferenceCount++;

    /* Release the lock */
    CsrReleaseNtSessionLock();
}

/*++
 * @name CsrDereferenceNtSession
 *
 * The CsrDereferenceNtSession decreases the reference count of a
 * CSR NT Session.
 *
 * @param Session
 *        Pointer to the CSR NT Session to reference.
 *
 * @param ExitStatus
 *        If this is the last reference to the session, this argument
 *        specifies the exit status.
 *
 * @return None.
 *
 * @remarks CsrDereferenceNtSession will complete the session if
 *          the last reference to it has been closed.
 *
 *--*/
VOID
NTAPI
CsrDereferenceNtSession(IN PCSR_NT_SESSION Session,
                        IN NTSTATUS ExitStatus)
{
    /* Acquire the lock */
    CsrAcquireNtSessionLock();

    /* Sanity checks */
    ASSERT(!IsListEmpty(&Session->SessionLink));
    ASSERT(Session->SessionId != 0);
    ASSERT(Session->ReferenceCount != 0);

    /* Dereference the Session Object */
    if ((--Session->ReferenceCount) == 0)
    {
        /* Remove it from the list */
        RemoveEntryList(&Session->SessionLink);

        /* Release the lock */
        CsrReleaseNtSessionLock();

        /* Tell SM that we're done here */
        SmSessionComplete(CsrSmApiPort, Session->SessionId, ExitStatus);

        /* Free the Session Object */
        RtlFreeHeap(CsrHeap, 0, Session);
    }
    else
    {
        /* Release the lock, the Session is still active */
        CsrReleaseNtSessionLock();
    }
}

/* SESSION MANAGER FUNCTIONS **************************************************/


static
PCSR_NT_SESSION
NTAPI
CsrLocateNtSessionById(IN ULONG SessionId,
                       IN BOOLEAN ReferenceSession)
{
    PLIST_ENTRY NextEntry;
    PCSR_NT_SESSION NtSession = NULL;

    CsrAcquireNtSessionLock();

    NextEntry = CsrNtSessionList.Flink;
    while (NextEntry != &CsrNtSessionList)
    {
        NtSession = CONTAINING_RECORD(NextEntry, CSR_NT_SESSION, SessionLink);
        if (NtSession->SessionId == SessionId)
        {
            if (ReferenceSession) NtSession->ReferenceCount++;
            break;
        }

        NtSession = NULL;
        NextEntry = NextEntry->Flink;
    }

    CsrReleaseNtSessionLock();
    return NtSession;
}

static
NTSTATUS
NTAPI
CsrGetProcessSessionId(IN HANDLE ProcessHandle,
                       OUT PULONG SessionId)
{
    PROCESS_SESSION_INFORMATION SessionInformation;
    NTSTATUS Status;

    Status = NtQueryInformationProcess(ProcessHandle,
                                       ProcessSessionInformation,
                                       &SessionInformation,
                                       sizeof(SessionInformation),
                                       NULL);
    if (!NT_SUCCESS(Status)) return Status;

    *SessionId = SessionInformation.SessionId;
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
CsrReferenceSingleActiveNtSession(OUT PCSR_NT_SESSION *NtSession)
{
    PLIST_ENTRY NextEntry;
    PCSR_NT_SESSION CurrentSession = NULL;

    *NtSession = NULL;

    CsrAcquireNtSessionLock();

    NextEntry = CsrNtSessionList.Flink;
    while (NextEntry != &CsrNtSessionList)
    {
        CurrentSession = CONTAINING_RECORD(NextEntry, CSR_NT_SESSION, SessionLink);

        if (!(CurrentSession->Flags & CsrNtSessionTerminating))
        {
            if (*NtSession)
            {
                CsrReleaseNtSessionLock();
                DPRINT1("CSRSS: Multiple active NT sessions present, cannot pick a unique target\n");
                return STATUS_INVALID_PARAMETER;
            }

            CurrentSession->ReferenceCount++;
            *NtSession = CurrentSession;
        }

        NextEntry = NextEntry->Flink;
    }

    CsrReleaseNtSessionLock();

    if (!*NtSession)
    {
        DPRINT1("CSRSS: No active NT session available for process creation\n");
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}


/*++
 * @name CsrSbCreateSession
 *
 * The CsrSbCreateSession API is called by the Session Manager whenever a new
 * session is created.
 *
 * @param ApiMessage
 *        Pointer to the Session Manager API Message.
 *
 * @return TRUE in case of success, FALSE otherwise.
 *
 * @remarks The CsrSbCreateSession routine will initialize a new CSR NT
 *          Session and allocate a new CSR Process for the subsystem process.
 *
 *--*/
BOOLEAN
NTAPI
CsrSbCreateSession(IN PSB_API_MSG ApiMessage)
{
    PSB_CREATE_SESSION_MSG CreateSession = &ApiMessage->u.CreateSession;
    HANDLE hProcess, hThread;
    PCSR_PROCESS CsrProcess;
    PCSR_THREAD CsrThread;
    PCSR_SERVER_DLL ServerDll;
    PVOID ProcessData;
    NTSTATUS Status;
    KERNEL_USER_TIMES KernelTimes;
    ULONG i;

    /* Save the Process and Thread Handles */
    hProcess = CreateSession->ProcessInfo.ProcessHandle;
    hThread = CreateSession->ProcessInfo.ThreadHandle;

    /* Lock the Processes */
    CsrAcquireProcessLock();

    /* Allocate a new process */
    CsrProcess = CsrAllocateProcess();
    if (!CsrProcess)
    {
        /* Fail */
        ApiMessage->ReturnValue = STATUS_NO_MEMORY;
        CsrReleaseProcessLock();
        return TRUE;
    }

    /* Set the Exception Port for us */
    Status = NtSetInformationProcess(hProcess,
                                     ProcessExceptionPort,
                                     &CsrApiPort,
                                     sizeof(CsrApiPort));

    /* Check for success */
    if (!NT_SUCCESS(Status))
    {
        /* Fail the request */
        CsrDeallocateProcess(CsrProcess);
        CsrReleaseProcessLock();

        /* Strange as it seems, NTSTATUSes are actually returned */
        return (BOOLEAN)STATUS_NO_MEMORY;
    }

    /* Get the Create Time */
    Status = NtQueryInformationThread(hThread,
                                      ThreadTimes,
                                      &KernelTimes,
                                      sizeof(KernelTimes),
                                      NULL);

    /* Check for success */
    if (!NT_SUCCESS(Status))
    {
        /* Fail the request */
        CsrDeallocateProcess(CsrProcess);
        CsrReleaseProcessLock();

        /* Strange as it seems, NTSTATUSes are actually returned */
        return (BOOLEAN)Status;
    }

    /* Allocate a new Thread */
    CsrThread = CsrAllocateThread(CsrProcess);
    if (!CsrThread)
    {
        /* Fail the request */
        CsrDeallocateProcess(CsrProcess);
        CsrReleaseProcessLock();

        ApiMessage->ReturnValue = STATUS_NO_MEMORY;
        return TRUE;
    }

    /* Setup the Thread Object */
    CsrThread->CreateTime = KernelTimes.CreateTime;
    CsrThread->ClientId = CreateSession->ProcessInfo.ClientId;
    CsrThread->ThreadHandle = hThread;
    ProtectHandle(hThread);
    CsrThread->Flags = 0;

    /* Insert it into the Process List */
    Status = CsrInsertThread(CsrProcess, CsrThread);
    if (!NT_SUCCESS(Status))
    {
        /* Bail out */
        CsrDeallocateProcess(CsrProcess);
        CsrDeallocateThread(CsrThread);
        CsrReleaseProcessLock();

        /* Strange as it seems, NTSTATUSes are actually returned */
        return (BOOLEAN)Status;
    }

    /* Setup Process Data */
    CsrProcess->ClientId = CreateSession->ProcessInfo.ClientId;
    CsrProcess->ProcessHandle = hProcess;
    CsrProcess->NtSession = CsrAllocateNtSession(CreateSession->SessionId);

    /* Set the Process Priority */
    CsrSetBackgroundPriority(CsrProcess);

    /* Get the first data location */
    ProcessData = &CsrProcess->ServerData[CSR_SERVER_DLL_MAX];

    /* Loop every DLL */
    for (i = 0; i < CSR_SERVER_DLL_MAX; i++)
    {
        /* Get the current Server */
        ServerDll = CsrLoadedServerDll[i];

        /* Check if the DLL is loaded and has Process Data */
        if (ServerDll && ServerDll->SizeOfProcessData)
        {
            /* Write the pointer to the data */
            CsrProcess->ServerData[i] = ProcessData;

            /* Move to the next data location */
            ProcessData = (PVOID)((ULONG_PTR)ProcessData +
                                  ServerDll->SizeOfProcessData);
        }
        else
        {
            /* Nothing for this Process */
            CsrProcess->ServerData[i] = NULL;
        }
    }

    /* Insert the Process */
    CsrInsertProcess(NULL, CsrProcess);

    /* Activate the Thread */
    ApiMessage->ReturnValue = NtResumeThread(hThread, NULL);

    /* Release lock and return */
    CsrReleaseProcessLock();
    return TRUE;
}

/*++
 * @name CsrSbForeignSessionComplete
 *
 * The CsrSbForeignSessionComplete API is called by the Session Manager
 * whenever a foreign session is completed (ie: terminated).
 *
 * @param ApiMessage
 *        Pointer to the Session Manager API Message.
 *
 * @return TRUE in case of success, FALSE otherwise.
 *
 * @remarks The CsrSbForeignSessionComplete API is not yet implemented.
 *
 *--*/
BOOLEAN
NTAPI
CsrSbForeignSessionComplete(IN PSB_API_MSG ApiMessage)
{
    ULONG SessionId = ApiMessage->u.ForeignSessionComplete.SessionId;
    PCSR_NT_SESSION NtSession;

    NtSession = CsrLocateNtSessionById(SessionId, FALSE);
    if (!NtSession)
    {
        DPRINT1("CSRSS: SbForeignSessionComplete for unknown session %lu\n", SessionId);
        ApiMessage->ReturnValue = STATUS_NOT_FOUND;
        return TRUE;
    }

    CsrAcquireNtSessionLock();
    NtSession->Flags |= CsrNtSessionForeignCompleted;
    CsrReleaseNtSessionLock();

    DPRINT1("CSRSS: SbForeignSessionComplete for session %lu\n", SessionId);
    ApiMessage->ReturnValue = STATUS_SUCCESS;
    return TRUE;
}

/*++
 * @name CsrSbTerminateSession
 *
 * The CsrSbTerminateSession API is called by the Session Manager
 * whenever a foreign session should be destroyed.
 *
 * @param ApiMessage
 *        Pointer to the Session Manager API Message.
 *
 * @return TRUE in case of success, FALSE otherwise.
 *
 * @remarks The CsrSbTerminateSession API is not yet implemented.
 *
 *--*/
BOOLEAN
NTAPI
CsrSbTerminateSession(IN PSB_API_MSG ApiMessage)
{
    PCSR_NT_SESSION NtSession;
    PCSR_PROCESS CsrProcess;
    PLIST_ENTRY NextEntry;
    NTSTATUS Status = STATUS_SUCCESS;
    NTSTATUS LocalStatus;
    LARGE_INTEGER Timeout;
    ULONG SessionId = ApiMessage->u.TerminateSession.SessionId;

    NtSession = CsrLocateNtSessionById(SessionId, TRUE);
    if (!NtSession)
    {
        DPRINT1("CSRSS: SbTerminateSession for unknown session %lu\n", SessionId);
        ApiMessage->ReturnValue = STATUS_NOT_FOUND;
        return TRUE;
    }

    CsrAcquireNtSessionLock();
    NtSession->Flags |= CsrNtSessionTerminating;
    CsrReleaseNtSessionLock();

    DPRINT1("CSRSS: SbTerminateSession start for session %lu\n", SessionId);

    CsrAcquireProcessLock();
    NextEntry = CsrRootProcess->ListLink.Flink;
    while (NextEntry != &CsrRootProcess->ListLink)
    {
        CsrProcess = CONTAINING_RECORD(NextEntry, CSR_PROCESS, ListLink);
        NextEntry = NextEntry->Flink;

        if (CsrProcess->NtSession != NtSession) continue;

        CsrLockedReferenceProcess(CsrProcess);
        CsrReleaseProcessLock();

        DPRINT1("CSRSS: Terminating session %lu process PID=%p\n",
                SessionId,
                CsrProcess->ClientId.UniqueProcess);

        LocalStatus = CsrDestroyProcess(&CsrProcess->ClientId, STATUS_SUCCESS);
        if (!NT_SUCCESS(LocalStatus) && (LocalStatus != STATUS_THREAD_IS_TERMINATING))
        {
            DPRINT1("CSRSS: CsrDestroyProcess failed for PID=%p with status %lx\n",
                    CsrProcess->ClientId.UniqueProcess,
                    LocalStatus);
            Status = LocalStatus;
        }

        Timeout.QuadPart = Int32x32To64(-1, 2 * 1000 * 1000 * 10);
        LocalStatus = NtWaitForSingleObject(CsrProcess->ProcessHandle, FALSE, &Timeout);
        if (LocalStatus == STATUS_TIMEOUT)
        {
            DPRINT1("CSRSS: Session %lu process PID=%p timed out; force-kill\n",
                    SessionId,
                    CsrProcess->ClientId.UniqueProcess);

            LocalStatus = NtTerminateProcess(CsrProcess->ProcessHandle,
                                             STATUS_PROCESS_IS_TERMINATING);
            if (!NT_SUCCESS(LocalStatus))
            {
                DPRINT1("CSRSS: Force-kill failed for PID=%p with status %lx\n",
                        CsrProcess->ClientId.UniqueProcess,
                        LocalStatus);
                Status = LocalStatus;
            }
            else
            {
                Timeout.QuadPart = Int32x32To64(-1, 1 * 1000 * 1000 * 10);
                LocalStatus = NtWaitForSingleObject(CsrProcess->ProcessHandle,
                                                    FALSE,
                                                    &Timeout);
                if (!NT_SUCCESS(LocalStatus))
                {
                    DPRINT1("CSRSS: Post kill wait failed for PID=%p with status %lx\n",
                            CsrProcess->ClientId.UniqueProcess,
                            LocalStatus);
                    Status = LocalStatus;
                }
            }
        }
        else if (!NT_SUCCESS(LocalStatus))
        {
            DPRINT1("CSRSS: Wait failed for PID=%p with status %lx\n",
                    CsrProcess->ClientId.UniqueProcess,
                    LocalStatus);
            Status = LocalStatus;
        }
        else
        {
            DPRINT("CSRSS: Session %lu process PID=%p terminated cleanly\n",
                   SessionId,
                   CsrProcess->ClientId.UniqueProcess);
        }

        CsrDereferenceProcess(CsrProcess);
        CsrAcquireProcessLock();
    }
    CsrReleaseProcessLock();

    CsrDereferenceNtSession(NtSession, Status);

    DPRINT1("CSRSS: SbTerminateSession complete for session %lu status %lx\n",
            SessionId,
            Status);

    ApiMessage->ReturnValue = Status;
    return TRUE;
}

/*++
 * @name CsrSbCreateProcess
 *
 * The CsrSbCreateProcess API is called by the Session Manager
 * whenever a foreign session is created and a new process should be started.
 *
 * @param ApiMessage
 *        Pointer to the Session Manager API Message.
 *
 * @return TRUE in case of success, FALSE otherwise.
 *
 * @remarks The CsrSbCreateProcess API is not yet implemented.
 *
 *--*/
BOOLEAN
NTAPI
CsrSbCreateProcess(IN PSB_API_MSG ApiMessage)
{
    PSB_CREATE_PROCESS_MSG CreateProcess = &ApiMessage->u.CreateProcess;
    PCSR_NT_SESSION NtSession;
    NTSTATUS Status;
    ULONG ProcessSessionId;

    Status = CsrReferenceSingleActiveNtSession(&NtSession);
    if (!NT_SUCCESS(Status))
    {
        ApiMessage->ReturnValue = Status;
        return TRUE;
    }

    if (!CreateProcess->Out.ProcessHandle ||
        !CreateProcess->Out.ThreadHandle ||
        !CreateProcess->Out.ClientId.UniqueProcess ||
        !CreateProcess->Out.ClientId.UniqueThread)
    {
        DPRINT1("CSRSS: SbCreateProcess in image-launch mode is not yet supported; session %lu\n",
                NtSession->SessionId);
        CsrDereferenceNtSession(NtSession, STATUS_SUCCESS);
        ApiMessage->ReturnValue = STATUS_NOT_IMPLEMENTED;
        return TRUE;
    }

    Status = CsrGetProcessSessionId(CreateProcess->Out.ProcessHandle,
                                    &ProcessSessionId);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSS: SbCreateProcess failed to query process session for PID=%p: %lx\n",
                CreateProcess->Out.ClientId.UniqueProcess,
                Status);
        CsrDereferenceNtSession(NtSession, STATUS_SUCCESS);
        ApiMessage->ReturnValue = Status;
        return TRUE;
    }

    if (ProcessSessionId != NtSession->SessionId)
    {
        DPRINT1("CSRSS: SbCreateProcess inconsistent session. expected=%lu actual=%lu PID=%p\n",
                NtSession->SessionId,
                ProcessSessionId,
                CreateProcess->Out.ClientId.UniqueProcess);
        CsrDereferenceNtSession(NtSession, STATUS_SUCCESS);
        ApiMessage->ReturnValue = STATUS_INVALID_PARAMETER;
        return TRUE;
    }

    Status = CsrCreateProcess(CreateProcess->Out.ProcessHandle,
                              CreateProcess->Out.ThreadHandle,
                              &CreateProcess->Out.ClientId,
                              NtSession,
                              0,
                              NULL);

    CsrDereferenceNtSession(NtSession, STATUS_SUCCESS);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSS: SbCreateProcess failed for PID=%p session=%lu status=%lx\n",
                CreateProcess->Out.ClientId.UniqueProcess,
                ProcessSessionId,
                Status);
    }
    else
    {
        DPRINT("CSRSS: SbCreateProcess success for PID=%p session=%lu\n",
               CreateProcess->Out.ClientId.UniqueProcess,
               ProcessSessionId);
    }

    ApiMessage->ReturnValue = Status;
    return TRUE;
}

/*++
 * @name CsrSbApiHandleConnectionRequest
 *
 * The CsrSbApiHandleConnectionRequest routine handles and accepts a new
 * connection request to the SM API LPC Port.
 *
 * @param ApiMessage
 *        Pointer to the incoming CSR API Message which contains the
 *        connection request.
 *
 * @return STATUS_SUCCESS in case of success, or status code which caused
 *         the routine to error.
 *
 * @remarks None.
 *
 *--*/
NTSTATUS
NTAPI
CsrSbApiHandleConnectionRequest(IN PSB_API_MSG Message)
{
    NTSTATUS Status;
    REMOTE_PORT_VIEW RemotePortView;
    HANDLE hPort;

    /* Set the Port View Structure Length */
    RemotePortView.Length = sizeof(REMOTE_PORT_VIEW);

    /* Accept the connection */
    Status = NtAcceptConnectPort(&hPort,
                                 NULL,
                                 &Message->h,
                                 TRUE,
                                 NULL,
                                 &RemotePortView);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSS: Sb Accept Connection failed %lx\n", Status);
        return Status;
    }

    /* Complete the Connection */
    Status = NtCompleteConnectPort(hPort);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSS: Sb Complete Connection failed %lx\n",Status);
    }

    /* Return status */
    return Status;
}

/*++
 * @name CsrSbApiRequestThread
 *
 * The CsrSbApiRequestThread routine handles incoming messages or connection
 * requests on the SM API LPC Port.
 *
 * @param Parameter
 *        System-default user-defined parameter. Unused.
 *
 * @return The thread exit code, if the thread is terminated.
 *
 * @remarks Before listening on the port, the routine will first attempt
 *          to connect to the user subsystem.
 *
 *--*/
VOID
NTAPI
CsrSbApiRequestThread(IN PVOID Parameter)
{
    NTSTATUS Status;
    SB_API_MSG ReceiveMsg;
    PSB_API_MSG ReplyMsg = NULL;
    PVOID PortContext;
    ULONG MessageType;

    /* Start the loop */
    while (TRUE)
    {
        /* Wait for a message to come in */
        Status = NtReplyWaitReceivePort(CsrSbApiPort,
                                        &PortContext,
                                        &ReplyMsg->h,
                                        &ReceiveMsg.h);

        /* Check if we didn't get success */
        if (Status != STATUS_SUCCESS)
        {
            /* If we only got a warning, keep going */
            if (NT_SUCCESS(Status)) continue;

            /* We failed big time, so start out fresh */
            ReplyMsg = NULL;
            DPRINT1("CSRSS: ReceivePort failed - Status == %X\n", Status);
            continue;
        }

        /* Save the message type */
        MessageType = ReceiveMsg.h.u2.s2.Type;

        /* Check if this is a connection request */
        if (MessageType == LPC_CONNECTION_REQUEST)
        {
            /* Handle connection request */
            CsrSbApiHandleConnectionRequest(&ReceiveMsg);

            /* Start over */
            ReplyMsg = NULL;
            continue;
        }

        /* Check if the port died */
        if (MessageType == LPC_PORT_CLOSED)
        {
            /* Close the handle if we have one */
            if (PortContext) NtClose((HANDLE)PortContext);

            /* Client died, start over */
            ReplyMsg = NULL;
            continue;
        }
        else if (MessageType == LPC_CLIENT_DIED)
        {
            /* Client died, start over */
            ReplyMsg = NULL;
            continue;
        }

        /*
         * It's an API Message, check if it's within limits. If it's not,
         * the NT Behaviour is to set this to the Maximum API.
         */
        if (ReceiveMsg.ApiNumber > SbpMaxApiNumber)
        {
            ReceiveMsg.ApiNumber = SbpMaxApiNumber;
            DPRINT1("CSRSS: %lx is invalid Sb ApiNumber\n", ReceiveMsg.ApiNumber);
        }

        /* Reuse the message */
        ReplyMsg = &ReceiveMsg;

        /* Make sure that the message is supported */
        if (ReceiveMsg.ApiNumber < SbpMaxApiNumber)
        {
            /* Call the API */
            if (!CsrServerSbApiDispatch[ReceiveMsg.ApiNumber](&ReceiveMsg))
            {
                DPRINT1("CSRSS: %s Session Api called and failed\n",
                        CsrServerSbApiName[ReceiveMsg.ApiNumber]);

                /* It failed, so return nothing */
                ReplyMsg = NULL;
            }
        }
        else
        {
            /* We don't support this API Number */
            ReplyMsg->ReturnValue = STATUS_NOT_IMPLEMENTED;
        }
    }
}

/* EOF */
