rule EXPL_LNX_DirtyFrag_ForensicArtefacts_May26_RID36A9 : DEMO EXPLOIT LINUX {
   meta:
      description = "Detects DirtyFrag exploit code POC usage in Linux environments"
      author = "Florian Roth"
      reference = "https://github.com/V4bel/dirtyfrag/tree/master"
      date = "2026-05-08 17:05:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXPLOIT, LINUX"
      minimum_yara = "3.5.0"
      
   strings:
      $xa1 = "/V4bel/dirtyfrag.git" ascii
      $xa2 = "static const uint8_t shell_elf[PAYLOAD_LEN] = {" ascii
      $xa3 = "/usr/bin/su page-cache patched (entry 0x%x = shellcode)" ascii
   condition: 
      filesize < 800KB and 1 of ( $xa* )
}