rule EquationGroup_Toolset_Apr17__EAFU_ecwi_ESKE_EVFR_RPC2_4_RID3A9F : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 19:54:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3e181ca31f1f75a6244b8e72afaa630171f182fbe907df4f8b656cc4a31602f6"
      hash2 = "c4152f65e45ff327dade50f1ac3d3b876572a66c1ce03014f2877cea715d9afd"
      hash3 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "* Listening Post DLL %s() returned error code %d." fullword ascii
      $s1 = "WsaErrorTooManyProcesses" fullword ascii
      $s2 = "NtErrorMoreProcessingRequired" fullword ascii
      $s3 = "Connection closed by remote host (TCP Ack/Fin)" fullword ascii
      $s4 = "ServerErrorBadNamePassword" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of ( $s* ) or 1 of ( $x* ) )
}