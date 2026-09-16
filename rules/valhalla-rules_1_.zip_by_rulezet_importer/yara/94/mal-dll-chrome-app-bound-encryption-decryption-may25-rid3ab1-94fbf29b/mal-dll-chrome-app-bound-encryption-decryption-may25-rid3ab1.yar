rule MAL_DLL_Chrome_App_Bound_Encryption_Decryption_May25_RID3AB1 : DEMO EXE FILE G1006 MAL {
   meta:
      description = "Detects a DLL used to decrypt App-Bound Encrypted (ABE) cookies, passwords & payment methods from Chromium-based browsers, seen being used by Kats stealer"
      author = "MalGamy"
      reference = "Internal Research"
      date = "2025-05-19 19:57:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, G1006, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Failed to set proxy blanket." ascii
      $s2 = "Decryption failed. Last error:" ascii
      $s3 = "\\Google\\Chrome\\User Data\\Local State" ascii
      $op1 = { 48 39 F3 74 ?? 4C 89 E2 48 89 E9 E8 ?? ?? ?? ?? 48 89 C1 48 8B 00 B2 ?? 48 8B 40 ?? 48 C7 44 01 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 13 48 89 C1 E8 ?? ?? ?? ?? 48 FF C3 EB ?? 48 8D 54 24 ?? 48 89 F9 E8 ?? ?? ?? ?? 48 89 E9 E8 ?? ?? ?? ?? 48 89 F8 48 81 C4 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2MB and $op1 and 1 of ( $s* )
}