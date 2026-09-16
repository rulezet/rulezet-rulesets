rule PUA_VULN_Driver_Razerinc_Rzpnk_Rzpnk_F159_RID362F : DEMO EXE FILE {
   meta:
      description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - rzpnk.sys"
      author = "Florian Roth"
      reference = "https://github.com/magicsword-io/LOLDrivers"
      date = "2025-09-18 16:45:01"
      score = 40
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $ = { 00 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e [1-8] 00 52 00 61 00 7a 00 65 00 72 00 20 00 4f 00 76 00 65 00 72 00 6c 00 61 00 79 00 20 00 53 00 75 00 70 00 70 00 6f 00 72 00 74 } 
      $ = { 00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 [1-8] 00 52 00 61 00 7a 00 65 00 72 00 2c 00 20 00 49 00 6e 00 63 00 2e } 
      $ = { 00 46 00 69 00 6c 00 65 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e [1-8] 00 31 00 2e 00 30 00 2e 00 31 00 32 00 2e 00 31 00 30 00 31 00 37 00 37 } 
      $ = { 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e [1-8] 00 31 00 2e 00 30 00 2e 00 31 00 32 00 2e 00 31 00 30 00 31 00 37 00 37 } 
      $ = { 00 49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 [1-8] 00 52 00 7a 00 70 00 6e 00 6b } 
      $ = { 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 [1-8] 00 52 00 7a 00 70 00 6e 00 6b } 
      $ = { 00 4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 [1-8] 00 52 00 7a 00 70 00 6e 00 6b 00 2e 00 73 00 79 00 73 } 
      $ = { 00 4c 00 65 00 67 00 61 00 6c 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 [1-8] 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 43 00 29 00 20 00 32 00 30 00 31 00 30 00 2d 00 32 00 30 00 31 00 37 00 2e 00 20 00 52 00 61 00 7a 00 65 00 72 00 2c 00 20 00 49 00 6e 00 63 00 2e } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them
}