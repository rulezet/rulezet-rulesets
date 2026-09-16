rule PwDump_B_RID2A0F : DEMO EXE FILE HKTL T1003 {
   meta:
      description = "Detects a tool used by APT groups - file PwDump.exe"
      author = "Florian Roth"
      reference = "https://community.broadcom.com/home"
      date = "2016-09-08 03:16:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "3c796092f42a948018c3954f837b4047899105845019fce75a6e82bc99317982"
      tags = "DEMO, EXE, FILE, HKTL, T1003"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Usage: %s [-x][-n][-h][-o output_file][-u user][-p password][-s share] machineName" fullword ascii
      $x2 = "pwdump6 Version %s by fizzgig and the mighty group at foofus.net" fullword ascii
      $x3 = "where -x targets a 64-bit host" fullword ascii
      $x4 = "Couldn't delete target executable from remote machine: %d" fullword ascii
      $s1 = "lsremora64.dll" fullword ascii
      $s2 = "lsremora.dll" fullword ascii
      $s3 = "servpw.exe" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 400KB and 1 of ( $x* ) ) or ( 3 of them )
}