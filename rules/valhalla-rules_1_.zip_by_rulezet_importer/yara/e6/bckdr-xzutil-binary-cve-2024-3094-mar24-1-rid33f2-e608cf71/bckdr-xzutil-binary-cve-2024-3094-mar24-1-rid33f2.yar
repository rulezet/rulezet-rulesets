rule BCKDR_XZUtil_Binary_CVE_2024_3094_Mar24_1_RID33F2 : CVE_2024_3094 DEMO FILE {
   meta:
      description = "Detects injected code used by the backdoored XZ library (xzutil) CVE-2024-3094."
      author = "Florian Roth"
      reference = "https://www.openwall.com/lists/oss-security/2024/03/29/4"
      date = "2024-03-30 15:09:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "319feb5a9cddd81955d915b5632b4a5f8f9080281fb46e2f6d69d53f693c23ae"
      hash2 = "605861f833fc181c7cdcabd5577ddb8989bea332648a8f498b4eef89b8f85ad4"
      hash3 = "8fa641c454c3e0f76de73b7cc3446096b9c8b9d33d406d38b8ac76090b0344fd"
      tags = "CVE_2024_3094, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 48 8d 7c 24 08 f3 ab 48 8d 44 24 08 48 89 d1 4c 89 c7 48 89 c2 e8 ?? ?? ?? ?? 89 c2 } 
      $op2 = { 31 c0 49 89 ff b9 16 00 00 00 4d 89 c5 48 8d 7c 24 48 4d 89 ce f3 ab 48 8d 44 24 48 } 
      $op3 = { 4d 8b 6c 24 08 45 8b 3c 24 4c 8b 63 10 89 85 78 f1 ff ff 31 c0 83 bd 78 f1 ff ff 00 f3 ab 79 07 } 
      $xc1 = { F3 0F 1E FA 55 48 89 F5 4C 89 CE 53 89 FB 81 E7 00 00 00 80 48 83 EC 28 48 89 54 24 18 48 89 4C 24 10 } 
   condition: 
      uint16 ( 0 ) == 0x457f and ( all of ( $op* ) or $xc1 )
}