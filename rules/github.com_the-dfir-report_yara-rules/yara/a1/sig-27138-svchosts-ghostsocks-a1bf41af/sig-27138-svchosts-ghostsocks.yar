import "pe"
rule sig_27138_svchosts_ghostsocks {
   meta:
      description = "27138 - file svchosts.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/"
      date = "2025-01-23"
      hash1 = "b4ad5df385ee964fe9a800f2cdaa03626c8e8811ddb171f8e821876373335e63"
   strings:
      $x1 = "GoneDATAPING&lt;&gt;idle1080openStat.com.exe.bat.cmdquitallgallprootitabsbrk is LEAFbaseGOGC+Inf-Infcas1cas2cas3cas4cas5cas63125" ascii
      $x2 = "integer divide by zeroCountPagesInUse (test)ReadMetricsSlow (test)trace reader (blocked)send on closed channelgetenv before env " ascii
      $x3 = "goroutine profileAllThreadsSyscallGC assist markingselect (no cases)sync.RWMutex.Lockwait for GC cycle: missing method notetslee" ascii
      $x4 = "runtime: unable to acquire - semaphore out of syncmallocgc called with gcphase == _GCmarkterminationrecursive call during initia" ascii
      $x5 = "lization - linker skewattempt to execute system stack code on user stackcompileCallback: function argument frame too largewq" fullword ascii
      $x6 = "read on pipeunixicmpigmpftpshttppop3smtpIdleOpenPOSTEtag0x%xdateetagfromhostlinkvarypathHostDategzip%x" fullword ascii
      $x7 = "ee space/gc/scan/globals:bytes/gc/heap/frees:objectsscanstack - bad statusheadTailIndex overflowkernel32.dll not foundadvapi32.d" ascii
      $x8 = "activeSweepmheap.freeSpanLocked - invalid freeattempt to clear non-empty span setruntime: close polldesc w/o unblockruntime: in" fullword ascii
      $s9 = "(types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeassignment to entry in nil map/cpu/clas" ascii
      $s10 = "bad defer entry in panicbypassed recovery failedbindm in unexpected GOOSrunqsteal: runq overflowdouble traceGCSweepStartY" fullword ascii
      $s11 = "floating point errorGC sweep terminationResetDebugLog (test)chan send (nil chan)malloc during signalclose of nil channelnotetsle" ascii
      $s12 = "9runtime: typeBitsBulkBarrier without type/memory/classes/metadata/mspan/free:bytesruntime.SetFinalizer: second argument is gcSw" ascii
      $s13 = "mheap.freeSpanLocked - invalid free of user arena chunkcasfrom_Gscanstatus:top gp->status is not in scan state is currently not " ascii
      $s14 = "eSpanLocked - invalid span stateattempted to add zero-sized address rangeruntime: blocked read on closing polldescstopTheWorld: " ascii
      $s15 = "sweepWaiterstraceStringsspanSetSpinemspanSpecialgcBitsArenasmheapSpecialgcpacertracemadvdontneedharddecommitdumping heapchan rec" ascii
      $s16 = "sweepWaiterstraceStringsspanSetSpinemspanSpecialgcBitsArenasmheapSpecialgcpacertracemadvdontneedharddecommitdumping heapchan rec" ascii
      $s17 = "(types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeassignment to entry in nil map/cpu/cla" fullword ascii
      $s18 = "persistentalloc: align is too large/memory/classes/heap/released:bytesgreyobject: obj not pointer-alignedmismatched begin/end of" ascii
      $s19 = "nSoyomboTagalogTibetanTirhutaRadicalSHA-224SHA-256SHA-384SHA-512os/execruntime#internDES-CBCEd25519MD2-RSAMD5-RSAserial:2.5.4.62" ascii
      $s20 = "3Wwrite heap dumpasyncpreemptoffforce gc (idle)sync.Mutex.Lockmalloc deadlockruntime error: scan missed a gmisaligned maskrecove" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 24000KB and
      ( pe.imphash() == "4f2f006e2ecf7172ad368f8289dc96c1" or ( 1 of ($x*) or 4 of them ) )
}