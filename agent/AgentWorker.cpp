#include "../packages/Microsoft.O365.Security.Krabsetw.4.1.18/lib/native/include/krabs.hpp"

#include "TiMemAgent.h"
#include "AgentService.h"
#include "DetectionLogic.h"
#include "YaraInstance.h"

void report_detection(int detId, map<wstring, uint64_t> evt_body) {
    using std::to_string;

    std::string sDump;
    std::string sOutBody;

    std::string procId = to_string(evt_body[L"CallingProcessId"]);
    std::string procImage = get_pname(evt_body[L"CallingProcessId"]);
    std::string targetProcId = to_string(evt_body[L"TargetProcessId"]);
    std::string targetProcImage = get_pname(evt_body[L"TargetProcessId"]);
    std::string protMask = itohs(evt_body[L"ProtectionMask"]);
    std::string allocType = itohs(evt_body[L"AllocationType"]);
    std::string size = to_string(evt_body[L"RegionSize"]);
    std::string baseAddr = itohs(evt_body[L"BaseAddress"]);

    switch (detId) {
    case ALLOCVM_REMOTE_META_GENERIC:
        sDump = dump_memory_ascii(evt_body[L"TargetProcessId"], evt_body[L"BaseAddress"], MEM_STR_SIZE);
        sOutBody = "\n\n\n\n[7;31mANOMALOUS MEMORY ALLOCATION DETECTED[0m \n\n";
        sOutBody += "[+] Source:       " + procImage + " (PID: " + procId + ")\n";
        sOutBody += "[+] Target:       " + targetProcImage + " (PID: " + targetProcId + ")\n";
        sOutBody += "[+] Protection:   " + protMask + "\n";
        sOutBody += "[+] Allocation:   " + allocType + "\n";
        sOutBody += "[+] Region size:  " + size + "\n";
        sOutBody += "[+] Base address: " + baseAddr + "\n";
        sOutBody += "[+] MZ-header:    ";
        if (sDump.rfind("MZ", 0) == 0) {
            sOutBody += "[31mYES[0m\n\n";
        }
        else {
            sOutBody += "[33mNO[0m\n\n";
        }
        sOutBody += "[+] Memory at location: \n\n";
        sOutBody += sDump;
        break;
    case ALLOCVM_REMOTE_SIGNATURES:
    default:
        return;
    }

    if (sOutBody.empty()) {
        log_debug(L"TiMemAgent: Failed to report detection");
        return;
    }

    if (!agent_message(sOutBody)) {
        log_debug(L"TiMemAgent: Failed to send agent message");
    }
    return;
}

// Parse KERNEL_THREATINT_TASK_ALLOCVM_REMOTE
map<wstring, uint64_t> parse_allocvm_remote(krabs::schema schema, krabs::parser parser) {
    map<wstring, uint64_t> zero_map;
    map<wstring, uint64_t> allocation_fields = { {(wstring)L"CallingProcessId",0},
                                                 {(wstring)L"TargetProcessId",0},
                                                 {(wstring)L"AllocationType",0},
                                                 {(wstring)L"ProtectionMask",0},
                                                 {(wstring)L"RegionSize",0},
                                                 {(wstring)L"BaseAddress",0}
    };

    try {
        for (krabs::property property : parser.properties()) {
            std::wstring wsPropertyName = property.name();
            if (allocation_fields.find(wsPropertyName) != allocation_fields.end()) {
                switch (property.type()) {
                    case TDH_INTYPE_UINT32:
                        allocation_fields[wsPropertyName] = parser.parse<std::uint32_t>(wsPropertyName);
                        break; 
                    case TDH_INTYPE_POINTER:
                        allocation_fields[wsPropertyName] = parser.parse<krabs::pointer>(wsPropertyName).address;
                        break;
                }
            }
        }
        return allocation_fields;
    }
    catch (...) {
        log_debug(L"Error parsing the event\n");
        return zero_map;
    }
}

VOID parse_single_event(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    krabs::parser parser(schema);

    map<wstring, uint64_t> parsed_event;

    int eid = schema.event_id();

    switch (eid) {
        case KERNEL_THREATINT_TASK_ALLOCVM_REMOTE:
            parsed_event = parse_allocvm_remote(schema, parser);
            break;
        // Currently unsupported event types
        case KERNEL_THREATINT_TASK_PROTECTVM_REMOTE:
        case KERNEL_THREATINT_TASK_MAPVIEW_REMOTE:
        case KERNEL_THREATINT_TASK_QUEUEUSERAPC_REMOTE:
        case KERNEL_THREATINT_TASK_SETTHREADCONTEXT_REMOTE:
        case KERNEL_THREATINT_TASK_ALLOCVM_LOCAL:
        case KERNEL_THREATINT_TASK_PROTECTVM_LOCAL:
        case KERNEL_THREATINT_TASK_MAPVIEW_LOCAL:
        case KERNEL_THREATINT_TASK_QUEUEUSERAPC_LOCAL:
        case KERNEL_THREATINT_TASK_SETTHREADCONTEXT_LOCAL:
        case KERNEL_THREATINT_TASK_READVM_LOCAL:
        case KERNEL_THREATINT_TASK_WRITEVM_LOCAL:
        case KERNEL_THREATINT_TASK_READVM_REMOTE:
        case KERNEL_THREATINT_TASK_WRITEVM_REMOTE:
        default:
            return;
    }
    if (parsed_event.empty()) {
        log_debug(L"TiEtwAgent: Failed to parse an event\n");
    }
    else {
        detect_event(parsed_event, eid);
    }
    return;
}

DWORD agent_worker()
{
    DWORD ret{ 0 };
    log_debug(L"TiEtwAgent: Started the agent worker\n");

    krabs::user_trace trace(ETS_NAME);
    krabs::provider<> provider(L"Microsoft-Windows-Threat-Intelligence");
    krabs::event_filter filter(krabs::predicates::id_is((int)KERNEL_THREATINT_TASK_ALLOCVM_REMOTE));

    try {
        log_debug(L"TiEtwAgent: Setting up the trace session\n");
        provider.add_on_event_callback(parse_single_event);
        provider.add_filter(filter);
        trace.enable(provider);

        trace.start();
    }
    catch (...) {
        log_debug(L"TiEtwAgent: Failed to setup a trace session\n");
        trace.stop();
    }
   
    ret = GetLastError();
    return ret;
}
