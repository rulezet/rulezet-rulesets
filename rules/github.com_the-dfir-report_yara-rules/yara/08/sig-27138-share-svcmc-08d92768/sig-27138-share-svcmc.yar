import "pe"
rule sig_27138_share_svcmc {
   meta:
      description = "27138 - file svcmc.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/"
      date = "2025-01-23"
      hash1 = "ced4ee8a9814c243f0c157cda900def172b95bb4bc8535e480fe432ab84b9175"
   strings:
      $x1 = "GoneDATAPING&lt;&gt;idle1080openStat.com.exe.bat.cmdquitallgallprootitabsbrk is LEAFbaseGOGC+Inf-Infcas1cas2cas3cas4cas5cas63125" ascii
      $x2 = "SsAinteger divide by zeroCountPagesInUse (test)ReadMetricsSlow (test)trace reader (blocked)send on closed channelgetenv before e" ascii
      $x3 = "goroutine profileAllThreadsSyscallGC assist markingselect (no cases)sync.RWMutex.Lockwait for GC cycle: missing method notetslee" ascii
      $x4 = "{runtime: unable to acquire - semaphore out of syncmallocgc called with gcphase == _GCmarkterminationrecursive call during initi" ascii
      $x5 = "alization - linker skewattempt to execute system stack code on user stackcompileCallback: function argument frame too large" fullword ascii
      $x6 = "read on pipeunixicmpigmpftpshttppop3smtpIdleOpenPOSTEtag0x%xdateetagfromhostlinkvarypathHostDategzip%x" fullword ascii
      $x7 = "free space/gc/scan/globals:bytes/gc/heap/frees:objectsscanstack - bad statusheadTailIndex overflowkernel32.dll not foundadvapi3" fullword ascii
      $x8 = "activeSweepmheap.freeSpanLocked - invalid freeattempt to clear non-empty span setruntime: close polldesc w/o unblockruntime: in" fullword ascii
      $s9 = "t] (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeassignment to entry in nil map/cpu/c" ascii
      $s10 = "bad defer entry in panicbypassed recovery failedbindm in unexpected GOOSrunqsteal: runq overflowdouble traceGCSweepStartR\\" fullword ascii
      $s11 = "floating point errorGC sweep terminationResetDebugLog (test)chan send (nil chan)malloc during signalclose of nil channelnotetsle" ascii
      $s12 = "6runtime: typeBitsBulkBarrier without type/memory/classes/metadata/mspan/free:bytesruntime.SetFinalizer: second argument is gcSw" ascii
      $s13 = "eSpanLocked - invalid span stateattempted to add zero-sized address rangeruntime: blocked read on closing polldescstopTheWorld: " ascii
      $s14 = "mheap.freeSpanLocked - invalid free of user arena chunkcasfrom_Gscanstatus:top gp->status is not in scan state is currently not " ascii
      $s15 = "sweepWaiterstraceStringsspanSetSpinemspanSpecialgcBitsArenasmheapSpecialgcpacertracemadvdontneedharddecommitdumping heapchan rec" ascii
      $s16 = "sweepWaiterstraceStringsspanSetSpinemspanSpecialgcBitsArenasmheapSpecialgcpacertracemadvdontneedharddecommitdumping heapchan rec" ascii
      $s17 = "t] (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeassignment to entry in nil map/cpu/c" ascii
      $s18 = "fumari.dll" fullword ascii
      $s19 = "persistentalloc: align is too large/memory/classes/heap/released:bytesgreyobject: obj not pointer-alignedmismatched begin/end of" ascii
      $s20 = "write heap dumpasyncpreemptoffforce gc (idle)sync.Mutex.Lockmalloc deadlockruntime error: scan missed a gmisaligned maskrecovery" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 24000KB and
      ( pe.imphash() == "5ece094e7f2f03efa6f8d51d9a698823" and ( pe.exports("MainFunc") and pe.exports("_cgo_dummy_export") ) or ( 1 of ($x*) or 4 of them ) )
}