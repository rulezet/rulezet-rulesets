rule sig_27138_svcmc_svchosts_0 {
   meta:
      description = "27138 - from files svcmc.dll, svchosts.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/"
      date = "2025-01-23"
      hash1 = "ced4ee8a9814c243f0c157cda900def172b95bb4bc8535e480fe432ab84b9175"
      hash2 = "b4ad5df385ee964fe9a800f2cdaa03626c8e8811ddb171f8e821876373335e63"
   strings:
      $x1 = "goroutine profileAllThreadsSyscallGC assist markingselect (no cases)sync.RWMutex.Lockwait for GC cycle: missing method notetslee" ascii
      $x2 = "read on pipeunixicmpigmpftpshttppop3smtpIdleOpenPOSTEtag0x%xdateetagfromhostlinkvarypathHostDategzip%x" fullword ascii
      $x3 = "activeSweepmheap.freeSpanLocked - invalid freeattempt to clear non-empty span setruntime: close polldesc w/o unblockruntime: in" fullword ascii
      $s4 = "eSpanLocked - invalid span stateattempted to add zero-sized address rangeruntime: blocked read on closing polldescstopTheWorld: " ascii
      $s5 = "sweepWaiterstraceStringsspanSetSpinemspanSpecialgcBitsArenasmheapSpecialgcpacertracemadvdontneedharddecommitdumping heapchan rec" ascii
      $s6 = "sweepWaiterstraceStringsspanSetSpinemspanSpecialgcBitsArenasmheapSpecialgcpacertracemadvdontneedharddecommitdumping heapchan rec" ascii
      $s7 = "persistentalloc: align is too large/memory/classes/heap/released:bytesgreyobject: obj not pointer-alignedmismatched begin/end of" ascii
      $s8 = "shedworkbuf is not emptybad use of bucket.mpbad use of bucket.bpruntime: double waitws2_32.dll not foundforcegc: phase errorgopa" ascii
      $s9 = "pg on g0bad TinySizeClassg already scannedmark - bad statusscanobject n == 0swept cached spanmarkBits overflowRtlGetCurrentPeb" fullword ascii
      $s10 = "mheap.freeSpanLocked - invalid free of user arena chunkcasfrom_Gscanstatus:top gp->status is not in scan state is currently not " ascii
      $s11 = "runtime/rwmutex.go" fullword ascii
      $s12 = "runtime/internal/atomic.(*Pointer[go.shape.struct { runtime.stack runtime.stack; runtime.stackguard0 uintptr; runtime.stackguard" ascii
      $s13 = "*runtime.mutex" fullword ascii
      $s14 = "floating point errorGC sweep terminationResetDebugLog (test)chan send (nil chan)malloc during signalclose of nil channelnotetsle" ascii
      $s15 = "d errorrunlock of unlocked rwmutexsigsend: inconsistent statemakeslice: len out of rangemakeslice: cap out of rangegrowslice: le" ascii
      $s16 = "all goroutines stack tracenotewakeup - double wakeuppersistentalloc: size == 0/gc/cycles/total:gc-cyclesnegative idle mark worke" ascii
      $s17 = "IIIIIIIIIII" fullword wide 
      $s18 = "ABCDEFGHIJ" fullword wide 
      $s19 = "runtime.errorAddressString.Error" fullword ascii
      $s20 = "runqhead" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 24000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}