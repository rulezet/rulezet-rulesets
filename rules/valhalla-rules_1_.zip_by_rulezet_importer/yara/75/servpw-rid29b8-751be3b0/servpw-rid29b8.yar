rule servpw_RID29B8 : DEMO EXE FILE HKTL {
   meta:
      description = "Detects a tool used by APT groups - file servpw_RID29B8.exe"
      author = "Florian Roth"
      reference = "https://community.broadcom.com/home"
      date = "2016-09-08 00:51:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "97b39ac28794a7610ed83ad65e28c605397ea7be878109c35228c126d43e2f46"
      hash2 = "0f340b471ef34c69f5413540acd3095c829ffc4df38764e703345eb5e5020301"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Unable to open target process: %d, pid %d" fullword ascii
      $s2 = "LSASS.EXE" fullword wide
      $s3 = "WriteProcessMemory failed: %d" fullword ascii
      $s4 = "lsremora64.dll" fullword ascii
      $s5 = "CreateRemoteThread failed: %d" fullword ascii
      $s6 = "Thread code: %d, path: %s" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 3 of them ) or ( all of them )
}