rule EXPL_LNX_DirtyFrag_ForensicArtefacts_May26 {
   meta:
      description = "Detects DirtyFrag exploit code POC usage in Linux environments"
      author = "Florian Roth"
      reference = "https://github.com/V4bel/dirtyfrag/tree/master"
      date = "2026-05-08"
      score = 75
      id = "bda5e087-8eb7-55bd-a5ff-0eef91d63bcf"
   strings:
      $xa1 = "/V4bel/dirtyfrag.git" ascii
      $xa2 = "static const uint8_t shell_elf[PAYLOAD_LEN] = {" ascii
      $xa3 = "/usr/bin/su page-cache patched (entry 0x%x = shellcode)" ascii
   condition:
      filesize < 800KB
      and 1 of ($xa*)
}