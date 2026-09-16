import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_625_1_Tro_60 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_625_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_129_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_150_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_203_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_230_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_253_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_368_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_410_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_215.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_499.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_550.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_593.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_598.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_692.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_737.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_81.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0078241cdb8a2e5bc5dba2120d5b75be0f434e7fd1fd2012b43c92ea32214626"
    hash2       = "30f088be1fda7b136ba9d359a232eee25b6327e7f4b0b05cc1a631e8c9078643"
    hash3       = "da1e0443018cd9c7d4088863bf6b5d87a3f8064d2335e043a28d13b4e902465e"
    hash4       = "d878d6d6ed7d96d8eccb0084661fb46d0e96904c1bf313310052c3fa6fcb8cf0"
    hash5       = "04e3771554bc4e674bff0df6d38f16f0bc1c08a057043087f73def3797de7baf"
    hash6       = "fd010cd0aa6ae1eee0403372991ef5b2febcad117fe89f0e0f079daa1df7090a"
    hash7       = "aac7fe1706feab43f50e68563c2a062f9e0de2bda6cdf51be07a8e0bac0f6859"
    hash8       = "63b92543e93ac72d1890595c64f2798f674d1b3f7d1eddce04253289c665d0e7"
    hash9       = "12e3f9f3546ef334df9d30729d8b6a6cee001b2d60ed646e330b32ad935c0435"
    hash10      = "c9e0be0c0bd37c297829c469b1adea7abf4d9301a55d78bf34664519da12379f"
    hash11      = "a7b53a4300a62ac2ce65bfd005e4f4301a579739e9e76d08e9131652c29e9b2b"
    hash12      = "3ed4c1660e888c706f8e13d652f776ffaad2940bc88f42e0a5f29a2e2154ff04"
    hash13      = "158aff47f029025c6c0798168ee7917741da9853a27a978ff668171348d06405"
    hash14      = "469ecd1db4b9e8dde2a6ca7967606823adc90bd65c28280c76ff80e5a18aedd3"
    hash15      = "75bec504ffc6ac2162abaf67e2eeffc8fa8b75510875aa2551eb57b51cc21dc5"
    hash16      = "417998a4d3a40e68baf49e6ec010a8c323b9f418ae80d58340c52cdb4a5ca098"

  strings:
    $s1  = "CPN: Percussion Correlation" fullword wide
    $s2  = "Platform.?$WriteOnlyArray@P$AAVBeat@Core@MusicDna@Entertainment@Microsoft@@$00" fullword wide
    $s3  = "Platform.?$WriteOnlyArray@P$AAVPercussiveEvent@Core@MusicDna@Entertainment@Microsoft@@$00" fullword wide
    $s4  = "Fine Pitch (FP) Amplitude" fullword wide
    $s5  = "Coarse Pitch (CP) Amplitude" fullword wide
    $s6  = "CP: Amplitude F-Smoothed" fullword wide
    $s7  = "CP: Amplitude T-Smoothed" fullword wide
    $s8  = "CP: Amplitude Novelty" fullword wide
    $s9  = "CP: Amplitude Novelty F-Smoothed" fullword wide
    $s10 = "CPN: Amplitude Novelty Narrowed" fullword wide
    $s11 = "CPN: Amplitude Novelty Despeckled" fullword wide
    $s12 = "CPP: Percussion" fullword wide
    $s13 = "FP: Chromatogram" fullword wide
    $s14 = "FP: Non-transient Chromatogram" fullword wide
    $s15 = "RMS Power Smoothed" fullword wide
    $s16 = "RMS Power Novelty" fullword wide
    $s17 = "Kick Drum" fullword wide
    $s18 = "High Snare / Clap" fullword wide
    $s19 = "bad_alloc exception from music DNA" fullword wide
    $s20 = "out_of_range exception from music DNA" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "0b36fc85e0cb5e337c80982db5210969" and (8 of them)
    ) or (all of them)
}