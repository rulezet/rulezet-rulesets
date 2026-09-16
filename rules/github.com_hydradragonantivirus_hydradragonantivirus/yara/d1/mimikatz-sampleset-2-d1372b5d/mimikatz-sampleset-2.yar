rule Mimikatz_SampleSet_2: APT {
  meta:
    description = "Mimikatz Rule generated from a big Mimikatz sample set"
    author      = "Florian Roth - Florian Roth"
    hash        = "6f14b6744aad66ac017ab7733cdb51ad"
    score       = 50

  strings:
    $s0 = "notsupported" fullword
    $s1 = "getKerberos" fullword
    $s2 = "M(knN0123456789abcdefghijklmnopqrstuvwxyz" fullword
    $s3 = "getLiveSSPFunctions" fullword
    $s4 = "getKerberosFunctions" fullword
    $s5 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><tr"
    $s6 = ".?AV_System_error@std@@" fullword
    $s7 = "getCredmanFunctions" fullword
    $s8 = "find_tokens" fullword

  condition:
    all of them
}