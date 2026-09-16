rule APT_MAL_RU_Snake_Indicators_May23_1_RID3370 : APT DEMO G0010 MAL RUSSIA {
   meta:
      description = "Detects indicators found in Snake malware samples"
      author = "Florian Roth"
      reference = "https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF"
      date = "2023-05-10 14:47:51"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "10b854d66240d9ee1ce4296d2f7857d2b1c6f062ca836d13d777930d678b3ca6"
      hash2 = "15ac5a61fb3e751045de2d7f5ff26c673f3883e326cd1b3a63889984a4fb2a8f"
      hash3 = "315ec991709eb45eccf724dfe31bccb7affcac7f8e8007e688ba8d02827205e0"
      tags = "APT, DEMO, G0010, MAL, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\\\.\\%s\\\\" ascii fullword
      $s2 = "read_peer_nfo" ascii fullword
      $s3 = "rcv_buf=%d%c" ascii fullword
      $s4 = "%s: (0x%08x)" ascii fullword
      $s5 = "no_impersonate" ascii fullword
   condition: 
      all of them
}