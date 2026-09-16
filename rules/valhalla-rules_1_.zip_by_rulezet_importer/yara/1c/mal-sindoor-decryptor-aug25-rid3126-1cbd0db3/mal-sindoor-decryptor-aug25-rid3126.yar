rule MAL_Sindoor_Decryptor_Aug25_RID3126 : DEMO EXE FILE MAL {
   meta:
      description = "Detects AES decryptor used by Sindoor dropper related to APT 36"
      author = "Pezier Pierre-Henri"
      reference = "Internal Research"
      date = "2025-08-29 13:10:11"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Go build" 
      $s2 = "main.rc4EncryptDecrypt" 
      $s3 = "main.processFile" 
      $s4 = "main.deriveKeyAES" 
      $s5 = "use RC4 instead of AES" 
   condition: 
      filesize < 100MB and ( uint16 ( 0 ) == 0x5a4d or uint32be ( 0 ) == 0x7f454c46 or ( uint32be ( 0 ) == 0xcafebabe and uint32be ( 4 ) < 0x20 ) or uint32 ( 0 ) == 0xfeedface or uint32 ( 0 ) == 0xfeedfacf ) and all of them
}