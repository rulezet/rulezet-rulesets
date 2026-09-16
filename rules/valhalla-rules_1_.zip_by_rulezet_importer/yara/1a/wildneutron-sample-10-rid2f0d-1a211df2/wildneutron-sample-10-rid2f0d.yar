rule WildNeutron_Sample_10_RID2F0D : APT DEMO EXE FILE {
   meta:
      description = "Wild Neutron APT Sample Rule"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
      date = "2015-07-10 11:40:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $n1 = "/c for /L %%i in (1,1,2) DO ping 127.0.0.1 -n 3 & type %%windir%%\\notepad.exe > %s & del /f %s" fullword ascii
      $s1 = "%SYSTEMROOT%\\temp\\_dbg.tmp" fullword ascii
      $s2 = "%SYSTEMROOT%\\SysWOW64\\mspool.dll" fullword ascii
      $s3 = "%SYSTEMROOT%\\System32\\dpcore16t.dll" fullword ascii
      $s4 = "%SYSTEMROOT%\\System32\\wdigestEx.dll" fullword ascii
      $s5 = "%SYSTEMROOT%\\System32\\mspool.dll" fullword ascii
      $s6 = "%SYSTEMROOT%\\System32\\kernel32.dll" fullword ascii
      $s7 = "%SYSTEMROOT%\\SysWOW64\\iastor32.exe" fullword ascii
      $s8 = "%SYSTEMROOT%\\System32\\msvcse.exe" fullword ascii
      $s9 = "%SYSTEMROOT%\\System32\\mshtaex.exe" fullword ascii
      $s10 = "%SYSTEMROOT%\\System32\\iastor32.exe" fullword ascii
      $s11 = "%SYSTEMROOT%\\SysWOW64\\mshtaex.exe" fullword ascii
      $x1 = "wdigestEx.dll" fullword ascii
      $x2 = "dpcore16t.dll" fullword ascii
      $x3 = "mspool.dll" fullword ascii
      $x4 = "msvcse.exe" fullword ascii
      $x5 = "mshtaex.exe" fullword wide
      $x6 = "iastor32.exe" fullword ascii
      $y1 = "Installer.exe" fullword ascii
      $y2 = "Info: Process %s" fullword ascii
      $y3 = "Error: GetFileTime %s 0x%x" fullword ascii
      $y4 = "Install succeeded" fullword ascii
      $y5 = "Error: RegSetValueExA 0x%x" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and ( $n1 or ( 1 of ( $s* ) and 1 of ( $x* ) and 3 of ( $y* ) ) )
}