rule PUA_VULN_Driver_Netfiltersys_EDC6_RID3332 : DEMO EXE FILE {
   meta:
      description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - netfilter2.sys"
      author = "Florian Roth"
      reference = "https://github.com/magicsword-io/LOLDrivers"
      date = "2025-09-18 14:37:31"
      score = 40
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $ = { 00 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e [1-8] 00 57 00 59 00 4a 00 53 00 51 00 20 00 54 00 44 00 49 00 20 00 48 00 6f 00 6f 00 6b 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00 20 00 28 00 57 00 50 00 50 00 29 } 
      $ = { 00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 [1-8] 5b 8f 56 fe 65 e0 5f e7 } 
      $ = { 00 46 00 69 00 6c 00 65 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e [1-8] 00 31 00 2e 00 34 00 2e 00 39 00 2e 00 35 00 20 00 62 00 75 00 69 00 6c 00 74 00 20 00 62 00 79 00 3a 00 20 00 57 00 69 00 6e 00 44 00 44 00 4b } 
      $ = { 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e [1-8] 00 31 00 2e 00 35 00 2e 00 38 00 2e 00 30 } 
      $ = { 00 49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 [1-8] 00 6e 00 65 00 74 00 66 00 69 00 6c 00 74 00 65 00 72 00 32 00 2e 00 73 00 79 00 73 } 
      $ = { 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 [1-8] 65 e0 5f e7 52 a0 90 1f 56 68 9a 71 52 a8 65 87 4e f6 } 
      $ = { 00 4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 [1-8] 00 6e 00 65 00 74 00 66 00 69 00 6c 00 74 00 65 00 72 00 32 00 2e 00 73 00 79 00 73 } 
      $ = { 00 4c 00 65 00 67 00 61 00 6c 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 [1-8] 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 a9 00 20 00 77 00 79 00 6a 00 73 00 71 00 2e 00 63 00 6f 00 6d } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them
}