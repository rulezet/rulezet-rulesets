import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_eGY_augxLYc_19_2_VirusShare_277 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.eGY@augxLYc_19_2.vir, VirusShareBackDoorMeterpreter216.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ed907dbad20604899e87d9da0e41f1a3e87cba9d93533f736d0ef9f28639340"
    hash2       = "2209ac09da78031d7bdcd91b05041e41a2dcbd0f2c842aa839ba3d18480e2c01"

  strings:
    $s1 = " is currently not supported for use in system callbacksSOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zonescasfrom_Gscans" ascii
    $s2 = "morebuf={pc:advertise errorasyncpreemptoffforce gc (idle)key has expiredmalloc deadlockmisaligned maskmissing mcache?ms: gomaxpr" ascii
    $s3 = "ocs=network is downno medium foundno such processpreempt SPWRITErecovery failedruntime error: runtime: frame runtime: max = runt" ascii
    $s4 = "e to parking on channelruntime: CreateIoCompletionPort failed (errno= slice bounds out of range [::%x] with length %yCreateWaita" ascii
    $s5 = "runtime: head = runtime: nelems=schedule: in cgotime: bad [0-9]*workbuf is empty initialHeapLive= spinningthreads=, p.searchAddr" ascii
    $s6 = "garbage collection scangcDrain phase incorrectgo with non-empty frameindex out of range [%x]interrupted system callinvalid m->lo" ascii
    $s7 = "ime: min = runtimer: bad pscan missed a gstartm: m has pstopm holding p already; errno= mheap.sweepgen= not in ranges:" fullword ascii
    $s8 = "s:top gp->status is not in scan stategentraceback callback cannot be used with non-zero skipnewproc: function arguments too larg" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "c7269d59926fa4252270f407e4dab043" and (all of them)
    ) or (all of them)
}