rule WPR_loader_EXE_RID2C21 : DEMO EXE FILE HKTL {
   meta:
      description = "Windows Password Recovery - file loader.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-15 09:36:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e7d158d27d9c14a4f15a52ee5bf8aa411b35ad510b1b93f5e163ae7819c621e2"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Failed to get system process ID" fullword wide
      $s2 = "gLSASS.EXE" fullword wide
      $s3 = "WriteProcessMemory failed" fullword wide
      $s4 = "wow64 process NOT created" fullword wide
      $s5 = "\\ast.exe" wide
      $s6 = "Exit code=%s, status=%d" fullword wide
      $s7 = "VirtualProtect failed" fullword wide
      $s8 = "nSeDebugPrivilege" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 3 of them )
}