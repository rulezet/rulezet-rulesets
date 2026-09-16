rule Equation_Kaspersky_FannyWorm_RID3273 : APT DEMO EXE FILE G0020 T1543_003 fanny {
   meta:
      description = "Equation Group Malware - Fanny Worm"
      author = "Florian Roth"
      reference = "https://securelist.com/equation-the-death-star-of-malware-galaxy/68750/"
      date = "2015-02-16 14:05:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO, EXE, FILE, G0020, T1543_003, fanny"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "x:\\fanny.bmp" fullword ascii
      $s2 = "32.exe" fullword ascii
      $s3 = "d:\\fanny.bmp" fullword ascii
      $x1 = "c:\\windows\\system32\\kernel32.dll" fullword ascii
      $x2 = "System\\CurrentControlSet\\Services\\USBSTOR\\Enum" fullword ascii
      $x3 = "System\\CurrentControlSet\\Services\\PartMgr\\Enum" fullword ascii
      $x4 = "\\system32\\win32k.sys" wide
      $x5 = "\\AGENTCPD.DLL" ascii
      $x6 = "agentcpd.dll" fullword ascii
      $x7 = "PADupdate.exe" fullword ascii
      $x8 = "dll_installer.dll" fullword ascii
      $x9 = "\\restore\\" ascii
      $x10 = "Q:\\__?__.lnk" fullword ascii
      $x11 = "Software\\Microsoft\\MSNetMng" fullword ascii
      $x12 = "\\shelldoc.dll" ascii
      $x13 = "file size = %d bytes" fullword ascii
      $x14 = "\\MSAgent" ascii
      $x15 = "Global\\RPCMutex" fullword ascii
      $x16 = "Global\\DirectMarketing" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d ) and filesize < 300000 and ( ( 2 of ( $s* ) ) or ( 1 of ( $s* ) and 6 of ( $x* ) ) or ( 14 of ( $x* ) ) )
}