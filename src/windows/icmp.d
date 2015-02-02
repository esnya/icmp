///
module windows.icmp;

version(Windows) extern(System) {
    public import std.c.windows.windows;

    pragma(lib, "Iphlpapi.lib");

    // IPERxport.h
    alias IPAddr = ULONG;
    alias IPMask = ULONG;
    alias IP_STATUS = ULONG;

    enum IP_STATUS_BASE = 11000;
    enum IP_SUCCESS = 0;
    enum IP_BUF_TOO_SMALL = (IP_STATUS_BASE + 1);
    enum IP_DEST_NET_UNREACHABLE = (IP_STATUS_BASE + 2);
    enum IP_DEST_HOST_UNREACHABLE = (IP_STATUS_BASE + 3);
    enum IP_DEST_PROT_UNREACHABLE = (IP_STATUS_BASE + 4);
    enum IP_DEST_PORT_UNREACHABLE = (IP_STATUS_BASE + 5);
    enum IP_NO_RESOURCES = (IP_STATUS_BASE + 6);
    enum IP_BAD_OPTION = (IP_STATUS_BASE + 7);
    enum IP_HW_ERROR = (IP_STATUS_BASE + 8);
    enum IP_PACKET_TOO_BIG = (IP_STATUS_BASE + 9);
    enum IP_REQ_TIMED_OUT = (IP_STATUS_BASE + 10);
    enum IP_BAD_REQ = (IP_STATUS_BASE + 11);
    enum IP_BAD_ROUTE = (IP_STATUS_BASE + 12);
    enum IP_TTL_EXPIRED_TRANSIT = (IP_STATUS_BASE + 13);
    enum IP_TTL_EXPIRED_REASSEM = (IP_STATUS_BASE + 14);
    enum IP_PARAM_PROBLEM = (IP_STATUS_BASE + 15);
    enum IP_SOURCE_QUENCH = (IP_STATUS_BASE + 16);
    enum IP_OPTION_TOO_BIG = (IP_STATUS_BASE + 17);
    enum IP_BAD_DESTINATION = (IP_STATUS_BASE + 18);

    struct icmp_echo_reply {
        IPAddr  Address;            // Replying address
        ULONG   Status;             // Reply IP_STATUS
        ULONG   RoundTripTime;      // RTT in milliseconds
        USHORT  DataSize;           // Reply data size in bytes
        USHORT  Reserved;           // Reserved for system use
        PVOID   Data;               // Pointer to the reply data
        ip_option_information Options; // Reply options
    }
    alias ICMP_ECHO_REPLY = icmp_echo_reply;
    alias PICMP_ECHO_REPLY = icmp_echo_reply*;

    // Iphlapi.h
    struct ip_option_information {
        UCHAR  Ttl;
        UCHAR  Tos;
        UCHAR  Flags;
        UCHAR  OptionsSize;
        PUCHAR OptionsData;
    };
    alias IP_OPTION_INFORMATION = ip_option_information;
    alias PIP_OPTION_INFORMATION = ip_option_information*;


    DWORD GetIpErrorString(in IP_STATUS ErrorCode, WCHAR* Buffer, PDWORD Size);
    BOOL IcmpCloseHandle(in HANDLE IcmpHandle);
    DWORD IcmpParseReplies(in LPVOID ReplyBuffer, DWORD ReplySize);
    DWORD IcmpSendEcho2(in HANDLE IcmpHandle, in HANDLE Event, in PIO_APC_ROUTINE ApcRoutine, in PVOID ApcContext, in IPAddr DestinationAddress, in LPVOID RequestData, in WORD RequestSize, in PIP_OPTION_INFORMATION RequestOptions, LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout);
    DWORD IcmpSendEcho2Ex(in HANDLE IcmpHandle, in HANDLE Event, in PIO_APC_ROUTINE ApcRoutine, in PVOID ApcContext, in IPAddr SourceAddress, in IPAddr DestinationAddress, in LPVOID RequestData, in WORD RequestSize, in PIP_OPTION_INFORMATION RequestOptions, LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout); 
    HANDLE IcmpCreateFile();

    // winternl.h
    alias NTSTATUS = LONG;

    struct _IO_STATUS_BLOCK {
        union {
            NTSTATUS Status;
            PVOID Pointer;
        };

        ULONG_PTR Information;
    };
    alias IO_STATUS_BLOCK = _IO_STATUS_BLOCK;
    alias PIO_STATUS_BLOCK = _IO_STATUS_BLOCK*;

    alias PIO_APC_ROUTINE = void function(in PVOID ApcContext, in PIO_STATUS_BLOCK IoStatusBlock, ULONG Reserved);
}
