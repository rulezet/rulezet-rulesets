rule Equation_Kaspersky_EquationLaserInstaller_RID37BD : APT DEMO EXE FILE G0020 {
   meta:
      description = "Equation Group Malware - EquationLaser Installer"
      author = "Florian Roth"
      reference = "https://securelist.com/equation-the-death-star-of-malware-galaxy/68750/"
      date = "2015-02-16 17:51:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO, EXE, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Failed to get Windows version" fullword ascii
      $s1 = "lsasrv32.dll and lsass.exe" fullword wide
      $s2 = "\\\\%s\\mailslot\\%s" fullword ascii
      $s3 = "%d-%d-%d %d:%d:%d Z" fullword ascii
      $s4 = "lsasrv32.dll" fullword ascii
      $s6 = "%s %02x %s" fullword ascii
      $s7 = "VIEWERS" fullword ascii
      $s8 = "5.2.3790.220 (srv03_gdr.040918-1552)" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d ) and filesize < 250000 and 6 of ( $s* )
}