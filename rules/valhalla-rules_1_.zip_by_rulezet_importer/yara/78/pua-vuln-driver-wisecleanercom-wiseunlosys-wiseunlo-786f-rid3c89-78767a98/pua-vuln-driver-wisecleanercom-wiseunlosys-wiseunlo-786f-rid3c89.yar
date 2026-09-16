rule PUA_VULN_Driver_Wisecleanercom_Wiseunlosys_Wiseunlo_786F_RID3C89 : DEMO EXE FILE {
   meta:
      description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - WiseUnlo.sys"
      author = "Florian Roth"
      reference = "https://github.com/magicsword-io/LOLDrivers"
      date = "2025-09-18 21:16:01"
      score = 40
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $ = { 00 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e [1-8] 00 57 00 69 00 73 00 65 00 55 00 6e 00 6c 00 6f } 
      $ = { 00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 [1-8] 00 57 00 69 00 73 00 65 00 43 00 6c 00 65 00 61 00 6e 00 65 00 72 00 2e 00 63 00 6f 00 6d } 
      $ = { 00 46 00 69 00 6c 00 65 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e [1-8] 00 31 00 2e 00 30 00 2e 00 32 00 2e 00 31 00 33 } 
      $ = { 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e [1-8] 00 31 00 2e 00 30 00 2e 00 32 00 2e 00 31 00 33 } 
      $ = { 00 49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 [1-8] 00 57 00 69 00 73 00 65 00 55 00 6e 00 6c 00 6f 00 2e 00 73 00 79 00 73 } 
      $ = { 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 [1-8] 00 57 00 69 00 73 00 65 00 55 00 6e 00 6c 00 6f } 
      $ = { 00 4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 [1-8] 00 57 00 69 00 73 00 65 00 55 00 6e 00 6c 00 6f 00 2e 00 73 00 79 00 73 } 
      $ = { 00 4c 00 65 00 67 00 61 00 6c 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 [1-8] 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 a9 00 20 00 32 00 30 00 31 00 35 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them
}