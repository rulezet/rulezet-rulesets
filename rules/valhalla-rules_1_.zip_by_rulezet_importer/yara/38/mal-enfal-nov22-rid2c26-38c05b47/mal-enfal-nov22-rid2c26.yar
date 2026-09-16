rule MAL_Enfal_Nov22_RID2C26 : DEMO EXE FILE MAL {
   meta:
      description = "Detects a certain type of Enfal Malware"
      author = "Florian Roth"
      reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.enfal"
      date = "2015-02-10 09:36:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      hash1 = "42fa6241ab94c73c7ab386d600fae70da505d752daab2e61819a0142b531078a"
      hash2 = "bf433f4264fa3f15f320b35e773e18ebfe94465d864d3f4b2a963c3e5efd39c2"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $xop1 = { 00 00 83 c9 ff 33 c0 f2 ae f7 d1 49 b8 ff 8f 01 00 2b c1 } 
      $s1 = "POWERPNT.exe" fullword ascii
      $s2 = "%APPDATA%\\Microsoft\\Windows\\" ascii
      $s3 = "%HOMEPATH%" fullword ascii
      $s4 = "Server2008" fullword ascii
      $s5 = "%ComSpec%" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and ( 1 of ( $x* ) or 3 of ( $s* ) )
}