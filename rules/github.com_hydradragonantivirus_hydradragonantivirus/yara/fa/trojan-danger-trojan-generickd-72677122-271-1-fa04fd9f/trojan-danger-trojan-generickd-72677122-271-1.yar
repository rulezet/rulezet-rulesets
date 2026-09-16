rule Trojan_Danger_Trojan_GenericKD_72677122_271_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_271_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75f4e8e349e0790c527833db47183a9262f3ec2d3300eabead1dd855bb35ced4"

  strings:
    $x1  = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii
    $x2  = "file descriptor in bad statefindrunnable: netpoll with pforgetting unknown stream idfound pointer to free objectgcBgMarkWorker: " ascii
    $x3  = "VirtualQuery for stack base failedadding nil Certificate to CertPoolchacha20: wrong HChaCha20 key sizecrypto/aes: invalid buffer" ascii
    $x4  = "slice bounds out of range [:%x] with length %ystopTheWorld: not stopped (status != _Pgcstop)sysGrow bounds not aligned to palloc" ascii
    $x5  = "entersyscallexit status gcBitsArenasgcpacertracegetaddrinfowharddecommithost is downhttp2debug=1http2debug=2illegal seekinvalid " ascii
    $x6  = "tls: certificate used with invalid signature algorithmtls: server resumed a session with a different versionx509: cannot verify " ascii
    $x7  = "http: putIdleConn: keep alives disabledinternal error: exit hook invoked panicinvalid HTTP header value for header %qinvalid ind" ascii
    $x8  = " to unallocated span37252902984619140625Arabic Standard TimeAzores Standard TimeCertFindChainInStoreCertOpenSystemStoreWChangeSe" ascii
    $x9  = "http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing co" ascii
    $x10 = "(MISSING)(unknown), newval=, oldval=, size = , tail = -07:00:00244140625: status=AuthorityBassa_VahBhaiksukiClassINETCreateDCWCr" ascii
    $x11 = "streamSafe was not resetstructure needs cleaningtext/html; charset=utf-8unexpected buffer len=%vunpacking Question.Classupdate d" ascii
    $x12 = "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memoryIA5String contains i" ascii
    $x13 = "http: ContentLength=%d with Body length %dinsufficient data for resource body lengthlooking for beginning of object key stringmi" ascii
    $x14 = "Nyiakeng_Puachue_HmongPakistan Standard TimeParaguay Standard TimeRtlDeleteFunctionTableRtlGetNtVersionNumbersSakhalin Standard " ascii
    $x15 = "AdjustWindowRectAlready ReportedCloseEnhMetaFileConnectNamedPipeContent-EncodingContent-LanguageContent-Length: CopyEnhMetaFileW" ascii
    $x16 = "Temporary RedirectTerminateJobObjectTime.MarshalJSON: Time.MarshalText: UNKNOWN_SETTING_%dVariation_SelectorWriteProcessMemoryad" ascii
    $x17 = "unixpacketunknown pcuser-agentuser32.dllws2_32.dllyt-dlp.exe  of size   (targetpc= , plugin:  ErrCode=%v KiB work,  exp.) for  f" ascii
    $x18 = "os/exec.Command(bad TinySizeClassdecryption failedentersyscallblockexec format errorexec: killing Cmdexec: not startedfractional" ascii
    $x19 = "span set block with unpopped elements found in resettls: received a session ticket with invalid lifetimetls: server selected uns" ascii
    $x20 = "crypto/ecdh: bad X25519 remote ECDH input: low order pointcrypto/ecdh: internal error: converting the wrong key typecrypto/ellip" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}