rule MAL_LNX_PLAGUE_BACKDOOR_Jul25_RID2FEE : DEMO FILE LINUX MAL {
   meta:
      description = "Detects Plague backdoor ELF binaries, related to PAM authentication alteration."
      author = "Pezier Pierre-Henri"
      reference = "Internal Research"
      date = "2025-07-25 12:18:11"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-09-17"
      tags = "DEMO, FILE, LINUX, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "decrypt_phrase" 
      $s2 = "init_phrases" 
      $x1 = "captured_password" 
      $x2 = "updateklog" 
      $x3 = "init_cred_structs" 
      $xop1 = { 48 8b [4] 00 8b 00 3d ca b2 e9 f1 74 } 
   condition: 
      uint32be ( 0 ) == 0x7f454c46 and filesize < 1MB and 2 of them
}