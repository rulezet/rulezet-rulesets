rule MAL_NET_Katz_Stealer_Loader_May25_RID32FC : DEMO MAL katzstealer {
   meta:
      description = "Detects .NET based Katz stealer loader"
      author = "Jonathan Peters (cod3nym)"
      reference = "Internal Research"
      date = "2025-05-21 14:28:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MAL, katzstealer"
      minimum_yara = "3.5.0"
      
   strings:
      $x = "ExecutarMetodoVAI" ascii
      $s1 = "VirtualMachineDetector" ascii
      $s2 = "Wow64SetThreadContext_API" ascii
      $s3 = "nomedoarquivo" ascii
      $s4 = { 65 78 74 65 6E C3 A7 61 6F 00 } 
      $s5 = "payloadBuffer" ascii
      $s6 = "caminhovbs" ascii
   condition: 
      $x or 3 of ( $s* )
}