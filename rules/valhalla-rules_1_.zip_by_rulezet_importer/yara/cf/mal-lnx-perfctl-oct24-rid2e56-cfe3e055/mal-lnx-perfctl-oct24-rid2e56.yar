rule MAL_LNX_Perfctl_Oct24_RID2E56 : DEMO FILE LINUX MAL {
   meta:
      description = "Detects Perfctl malware samples"
      author = "Florian Roth"
      reference = "https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/"
      date = "2024-10-09 11:10:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a6d3c6b6359ae660d855f978057aab1115b418ed277bb9047cd488f9c7850747"
      hash2 = "ca3f246d635bfa560f6c839111be554a14735513e90b3e6784bedfe1930bdfd6"
      tags = "DEMO, FILE, LINUX, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 83 45 f8 01 8b 45 f8 48 3b 45 98 0f 82 1b ff ff ff 90 c9 c3 55 } 
      $op2 = { 48 8b 55 a0 48 01 ca 0f b6 0a 48 8b 55 a8 89 c0 88 4c 02 18 8b 45 fc 83 e0 3f } 
      $op3 = { 88 4c 10 58 83 45 f8 01 83 7d f8 03 0f 86 68 ff ff ff 90 c9 c3 55 } 
      $op4 = { 48 83 ec 68 48 89 7d a8 48 89 75 a0 48 89 55 98 48 8b 45 a8 48 8b 00 83 e0 3f 89 45 fc } 
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 300KB and 2 of them
}