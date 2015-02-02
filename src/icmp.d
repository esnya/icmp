///
module icmp;

import std.bitmanip;
import std.exception;
import std.range;
import std.socket;
import std.typecons;

version(Windows) {
    import windows.icmp;
    import std.windows.syserror;
} else version(Posix) {
    import std.socket;
    import std.c.string;
    import core.sys.posix.netinet.in_;

    enum BigEndianField(T, string FieldName) = 
        "private ubyte[" ~ T.sizeof.stringof ~ "] _" ~ FieldName ~ ";"
        "@property auto " ~ FieldName ~ "() const { return _" ~ FieldName ~ ".bigEndianToNative!(" ~ T.stringof ~ ")(); }"
        "@property auto " ~ FieldName ~ "(" ~ T.stringof ~  " value) { return _" ~ FieldName ~ " = value.nativeToBigEndian(); }"
        ;

    enum IP_TTL = 0x00000002;

    struct IPHeader {
        version(LittleEndian) {
            mixin(bitfields!(
                        ubyte, "hl", 4,
                        ubyte, "v", 4));
        } else version(BigEndian) {
            mixin(bitfields!(
                        ubyte, "v", 4,
                        ubyte, "hl", 4));
        }

        ubyte tos;

        mixin(BigEndianField!(ushort, "len"));
        mixin(BigEndianField!(ushort, "ip"));

        private ubyte[2] _flagsoff;
        @property auto df() const {
            return _flagsoff[0] & 0x40;
        }
        @property auto df(bool value) {
            if (value) {
                return _flagsoff[0] |= 0x40;
            } else {
                return _flagsoff[0] &= ~0x40;
            }
        }
        @property auto mf() const {
            return _flagsoff[0] & 0x20;
        }
        @property auto mf(bool value) {
            if (value) {
                return _flagsoff[0] |= 0x20;
            } else {
                return _flagsoff[0] &= ~0x20;
            }
        }
        @property auto off() const {
            return _flagsoff.bigEndianToNative!ushort() & (~0x6000);
        }
        @property auto off(ushort value) {
            auto big = value.nativeToBigEndian();
            _flagsoff[0] = big[0] & (~0x60) | (_flagsoff[0] & 0x60);
            _flagsoff[1] = big[1];
        }

        ubyte ttl;
        ubyte p;
        ubyte sum;
        uint src;
        uint dst;
    }

    struct ICMPEchoHeader {
        ubyte type;
        ubyte code;
        ubyte csum;
        mixin(BigEndianField!(ushort, "id"));
        mixin(BigEndianField!(ushort, "seq"));
    }

    enum ICMPType : ubyte {
        EchoReply = 0,
        DestinationUnreachable = 3,
        SourceQuench = 4,
        Redirect = 5,
        EchoRequest = 8,
        RouterAdvertisement = 9,
        RouterSoliciation = 10,
        TimeExceeded = 11,
        ParameterProblem = 12,
        Timestamp = 13,
        TimestampReply = 14,
        InformationRequest = 15,
        InformationReply = 16,
        AddressMaskRequest = 17,
        AddressMaskReply = 18,
    }

    enum ICMPUnreachableCode : ubyte {
        Network = 0,
        Host = 1,
        Protocol = 2,
        Port = 3,
        Fragmentation = 4,
        // ToDo
    }

    T checksum(T, U)(ref U data) {
        auto buf = cast(ushort*)&data;
        auto bufsz = T.sizeof;
        uint sum = 0;

        while (bufsz > 1) {
            sum += *buf;
            buf++;
            bufsz -= 2;
        }

        if (bufsz == 1) {
            sum += *cast(ubyte *)buf;
        }

        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);

        return cast(T)~sum;
    }
}

private int _lasterr() {
    version(Windows) {
        return GetLastError();
    } else {
        assert(0, "ToDo");
    }
}

version(unittest) {
    import std.stdio;
}

/// OS Exeption
class ICMPOSException : Exception {
    this(int err, string file = __FILE__, uint line = __LINE__) {
        this(null, file, line, err);
    }
    this(string msg = null, string file = __FILE__, uint line = __LINE__, int err = _lasterr()) {
        import std.string;

        version (Windows) {
            msg ~= format("(0x%08x) %s", err, sysErrorString(err));
        } else {
            char[80] buf;
            const(char)* cs;
            version (linux)
            {
                cs = strerror_r(err, buf.ptr, buf.length);
            }
            else version (OSX)
            {
                auto errs = strerror_r(err, buf.ptr, buf.length);
                if (errs == 0)
                    cs = buf.ptr;
                else
                    return "Socket error " ~ to!string(err);
            }
            else version (FreeBSD)
            {
                auto errs = strerror_r(err, buf.ptr, buf.length);
                if (errs == 0)
                    cs = buf.ptr;
                else
                    return "Socket error " ~ to!string(err);
            }
            else
                static assert(0);

            auto len = strlen(cs);

            if(cs[len - 1] == '\n')
                len--;
            if(cs[len - 1] == '\r')
                len--;
            msg = cs[0 .. len].idup;
        }
        super(msg, file, line);
    }
}

/// Random data generator
auto randomData(size_t size = 32) {
    import std.random;

    alias gen = uniform!ubyte;
    
    return (&gen).repeat().map!`a()`().take(size).array;
}

version (Windows) {
    /// Status code
    enum IPStatus {
        Success = 0,

        Base = 11000,

        BufferTooSmall = Base + 1,
        DestinationHostUnreachable = Base + 2,
        DestinationNetworkUnreachable = Base + 3,
        DestinationProtocolUnreachable = Base + 4,
        DestinationPortUnreachable = Base + 5,
        NoResources = Base + 6,
        BatOptions = Base + 7,
        HWError = Base + 8,
        PacketTooBig = Base + 9,
        RequestTimedOut = Base + 10,
        BadRequest = Base + 11,
        BadRoute = Base + 12,
        TTLExpriedTransit = Base + 13,
        TTLExpriedReassem = Base + 14,
        ParameterProbrem = Base + 15,
        SourceQuench = Base + 16,
        OptionTooBig = Base + 17,
        BadDestination = Base + 18,
    }
} else {
    /// Status code
    enum IPStatus {
        Success = 0,
        DestinationHostUnreachable,
        DestinationNetworkUnreachable,
        DestinationProtocolUnreachable,
        DestinationPortUnreachable,
        NoResources,
        BatOptions,
        HWError,
        PacketTooBig,
        RequestTimedOut,
        BadRequest,
        BadRoute,
        TTLExpriedTransit,
        TTLExpriedReassem,
        SourceQuench,
        OptionTooBig,
        BadDestination,
    }
}

/// Convert byte ordder
uint hostToNetworkOrder(uint hostOrder) {
    return (cast(uint[])cast(void[])hostOrder.nativeToBigEndian())[0];
}
/// ditto
uint networkToHostOrder(uint networkOrder) {
    return (cast(ubyte[])cast(void[])[networkOrder])[0..4].bigEndianToNative!uint();
}

/// Options for ping
struct PingOptions {
    uint timeout = 1000;
    ubyte ttl = 64;
}

/// ping
auto ping(InternetAddress address, void[] data, PingOptions options = PingOptions()) {
    alias ReturnType = Tuple!(IPStatus, "status", InternetAddress, "address", void[], "data", ubyte, "ttl", ubyte, "tos", ubyte, "flags");
    version(Windows) {
        auto handle = IcmpCreateFile().enforceEx!ICMPOSException();
        scope(exit) IcmpCloseHandle(handle);

        auto addr = (cast(uint[])cast(void[])address.addr.nativeToBigEndian())[0];

        auto dataSize = cast(ushort)(cast(ubyte[])data).length;
        auto replyBuffer = new ubyte[ICMP_ECHO_REPLY.sizeof + dataSize + 8];


        IP_OPTION_INFORMATION option;
        option.Ttl = options.ttl;

        auto retVal = IcmpSendEcho2(handle, null, null, null,
                addr, data.ptr, dataSize, &option,
                replyBuffer.ptr, replyBuffer.length, options.timeout);

        if (retVal!= 0) {
            auto reply = cast(ICMP_ECHO_REPLY*)replyBuffer.ptr;
            auto replyAddress = new InternetAddress(((cast(ubyte[])cast(void[])[reply.Address])[0..4]).bigEndianToNative!uint(), InternetAddress.PORT_ANY);

            auto status = cast(IPStatus)reply.Status;

            return ReturnType(status, replyAddress, replyBuffer[ICMP_ECHO_REPLY.sizeof .. $-8], reply.Options.Ttl, reply.Options.Tos, reply.Options.Flags);
        } else {
            auto err = _lasterr();
            switch(err) {
                case IP_BUF_TOO_SMALL:
                case IP_REQ_TIMED_OUT:
                    return ReturnType(cast(IPStatus)err, null, null, 0, 0, 0);
                default:
                    throw new ICMPOSException(err);
            }
        }
    } else {
        static uint id;
        static uint seq;

        ICMPEchoHeader requestHeader;
        requestHeader.type = ICMPType.EchoRequest;
        requestHeader.id = std.random.uniform!ushort();
        requestHeader.seq = std.random.uniform!ushort();
        requestHeader.csum = checksum!ubyte(requestHeader);

        auto socket = new Socket(AddressFamily.INET, SocketType.RAW, ProtocolType.ICMP);

        socket.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, dur!"msecs"(options.timeout));
        socket.setOption(SocketOptionLevel.IP, cast(SocketOption)IP_TTL, options.ttl);

        auto r = socket.sendTo(cast(void[])[requestHeader] ~ cast(void[])data, address);
        enforce(r > 0, socket.getErrorText());

        auto buf = new ubyte[20  + 8 + data.length + 20 + 8];
        r = socket.receive(buf);
        if (r <= 0) {
            return ReturnType(IPStatus.RequestTimedOut, null, null, 0, 0, 0);
        }
        buf = buf[0 .. r];

        auto replyIPHeader = cast(IPHeader*)buf.ptr;

        enforce(replyIPHeader.v == 4);
        enforce(replyIPHeader.hl == 20 / 4);
        enforce(replyIPHeader.p == 1);

        auto src = new InternetAddress(replyIPHeader.src.networkToHostOrder(), InternetAddress.PORT_ANY);

        auto replyHeader = cast(ICMPEchoHeader*)(buf.ptr + replyIPHeader.off + IPHeader.sizeof);// + replyIPHeader.hl * 4);

        auto replyData = buf[IPHeader.sizeof + replyIPHeader.off + ICMPEchoHeader.sizeof .. $];

        IPStatus status;
        with(ICMPType) {
            with(IPStatus) {
                switch (cast(ICMPType)replyHeader.type) {
                    case EchoReply:
                    case EchoRequest:
                        status = Success;
                        break;
                    case TimeExceeded:
                        status = TTLExpriedTransit;
                        break;
                    default:
                        throw new Exception("Unsupported ICMP type: "  ~ std.conv.to!string(cast(ICMPType)replyHeader.type));
                }
            }
        }

        return ReturnType(status, src, buf[IPHeader.sizeof + replyIPHeader.off + ICMPEchoHeader.sizeof .. $], replyIPHeader.ttl, replyIPHeader.tos, cast(ubyte)replyIPHeader.off);
    }
}
/// ditto
auto ping(InternetAddress address, size_t dataSize = 32, PingOptions options = PingOptions()) {
    return ping(address, randomData(32), options);
}
///
unittest {
    auto data = randomData();
    auto ret = ping(new InternetAddress("127.0.0.1", InternetAddress.PORT_ANY), data);
    assert(ret.status == IPStatus.Success);
    assert(ret.address.toAddrString() == "127.0.0.1");
    assert(ret.data == data);
}
unittest {
    auto ret = ping(new InternetAddress("192.0.2.1", InternetAddress.PORT_ANY));
    assert(ret.status == IPStatus.RequestTimedOut);
}
//unittest {
//    auto ret = ping(new InternetAddress("8.8.8.8", InternetAddress.PORT_ANY), 1000);
//    assert(ret.status == IPStatus.Success);
//    assert(ret.address.toAddrString() == "8.8.8.8");
//}

/// traceroute
auto traceroute(InternetAddress address, uint timeout = 1000, ubyte maxHop = 30) {
    return iota(1, maxHop+1).map!`cast(ubyte)a`().map!(ttl => ping(address, 0, PingOptions(timeout, ttl)))().until!(a => a.status == IPStatus.Success)().map!`a.address`().array;
}
///
unittest {
    assert(traceroute(new InternetAddress("127.0.0.1", 0)) == []);
    //assert(traceroute(new InternetAddress("192.30.252.128", 0)).length > 0);
    //writeln(traceroute(new InternetAddress("192.30.252.128", 0)));
}
