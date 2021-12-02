#include "DetectionLogic.h"
#include "Helpers.h"

/************************************************************************************************************
ADD NEW DETECTION RULES BELOW, BASED ON THE allocvm_remote_mega_generic EXAMPLE
FIELD DECLARATIONS FOR EACH EVENT TYPE CAN BE FOUND HERE
https://github.com/jdu2600/Windows10EtwEvents/blob/master/manifest/Microsoft-Windows-Threat-Intelligence.tsv
************************************************************************************************************/

// Simple detection relying on metadata of the allocated memory page
const int ALLOC_PROTECTION{ PAGE_EXECUTE_READWRITE };
const int ALLOC_TYPE{ MEM_RESERVE | MEM_COMMIT };
const int MIN_REGION_SIZE{ 10240 };

DWORD allocvm_remote_meta_generic(GenericEvent alloc_event) {
    if (alloc_event.fields[L"RegionSize"] >= MIN_REGION_SIZE) {
        if (alloc_event.fields[L"AllocationType"] == ALLOC_TYPE) {
            report_detection(ALLOCVM_REMOTE_META_GENERIC, alloc_event);
            return TRUE;
        }
    }
    return FALSE;
}

DWORD allocvm_local_meta_generic(GenericEvent alloc_event) {
    if (alloc_event.fields[L"RegionSize"] >= MIN_REGION_SIZE) {
        if (alloc_event.fields[L"AllocationType"] == ALLOC_TYPE) {
            if (alloc_event.fields[L"ProtectionMask"] == ALLOC_PROTECTION) {
                if (get_pname(alloc_event.fields[L"CallingProcessId"]).find("MsMpEng.exe") == std::string::npos) {
                    report_detection(ALLOCVM_LOCAL_META_GENERIC, alloc_event);
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

DWORD writevm_remote_meta_generic(GenericEvent alloc_event) {
    report_detection(WRITEVM_REMOTE, alloc_event);
    return TRUE;
}

DWORD protectvm_remote_meta_generic(GenericEvent alloc_event) {
    report_detection(PROTECTVM_REMOTE, alloc_event);
    return TRUE;
}

VOID detect_event(GenericEvent evt) {
    // Run detection functions depending on source event type
    switch (evt.type) {
        case KERNEL_THREATINT_TASK_ALLOCVM_REMOTE:
            log_debug(L"[*] KERNEL_THREATINT_TASK_ALLOCVM_REMOTE event *************\n");
            allocvm_remote_meta_generic(evt);
            break;
        case KERNEL_THREATINT_TASK_PROTECTVM_REMOTE:
            log_debug(L"[*] KERNEL_THREATINT_TASK_PROTECTVM_REMOTE event\n");
            protectvm_remote_meta_generic(evt);
            break;
        case KERNEL_THREATINT_TASK_MAPVIEW_REMOTE:
            log_debug(L"[*] KERNEL_THREATINT_TASK_MAPVIEW_REMOTE event\n");
            break;
        case KERNEL_THREATINT_TASK_QUEUEUSERAPC_REMOTE:
            log_debug(L"[*] KERNEL_THREATINT_TASK_QUEUEUSERAPC_REMOTE event\n");
            break;
        case KERNEL_THREATINT_TASK_SETTHREADCONTEXT_REMOTE:
            log_debug(L"[*] KERNEL_THREATINT_TASK_SETTHREADCONTEXT_REMOTE event\n");
            break;
        case KERNEL_THREATINT_TASK_ALLOCVM_LOCAL:
            log_debug(L"[*] KERNEL_THREATINT_TASK_ALLOCVM_LOCAL event\n");
            allocvm_local_meta_generic(evt);
            break;
        case KERNEL_THREATINT_TASK_PROTECTVM_LOCAL:
            log_debug(L"[*] KERNEL_THREATINT_TASK_PROTECTVM_LOCAL event\n");
            break;
        case KERNEL_THREATINT_TASK_MAPVIEW_LOCAL:
            log_debug(L"[*] KERNEL_THREATINT_TASK_ALLOCVM_REMOTE event\n");
            break;
        case KERNEL_THREATINT_TASK_QUEUEUSERAPC_LOCAL:
            log_debug(L"[*] KERNEL_THREATINT_TASK_QUEUEUSERAPC_LOCAL event\n");
            break;
        case KERNEL_THREATINT_TASK_SETTHREADCONTEXT_LOCAL:
            log_debug(L"[*] KERNEL_THREATINT_TASK_SETTHREADCONTEXT_LOCAL event\n");
            break;
        case KERNEL_THREATINT_TASK_READVM_LOCAL:
            log_debug(L"[*] KERNEL_THREATINT_TASK_READVM_LOCAL event\n");
            break;
        case KERNEL_THREATINT_TASK_WRITEVM_LOCAL:
            log_debug(L"[*] KERNEL_THREATINT_TASK_WRITEVM_LOCAL event\n");
            break;
        case KERNEL_THREATINT_TASK_READVM_REMOTE:
            log_debug(L"[*] KERNEL_THREATINT_TASK_READVM_REMOTE event\n");
            break;
        case KERNEL_THREATINT_TASK_WRITEVM_REMOTE:
            log_debug(L"[*] KERNEL_THREATINT_TASK_WRITEVM_REMOTE event\n");
            writevm_remote_meta_generic(evt);
            break;
        default:
            break;
    }
}
