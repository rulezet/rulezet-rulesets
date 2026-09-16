rule MAL_NET_Katz_Stealer_Loader_May25 {
   meta:
      description = "Detects .NET based Katz stealer loader"
      author = "Jonathan Peters (cod3nym)"
      date = "2025-05-21"
      reference = "Internal Research"
      hash = "0df13fd42fb4a4374981474ea87895a3830eddcc7f3bd494e76acd604c4004f7"
      score = 80
   strings:
      $x = "ExecutarMetodoVAI" ascii

      $s1 = "VirtualMachineDetector" ascii
      $s2 = "Wow64SetThreadContext_API" ascii
      $s3 = "nomedoarquivo" ascii
      $s4 = { 65 78 74 65 6E C3 A7 61 6F 00 }
      $s5 = "payloadBuffer" ascii
      $s6 = "caminhovbs" ascii
   condition:
      3 of ($s*) or $x
}