rule Fireball_archer_RID2D06 : APT DEMO EXE FILE {
   meta:
      description = "Detects Fireball malware - file archer.dll"
      author = "Florian Roth"
      reference = "https://blog.checkpoint.com/research/fireball-chinese-malware-250-million-infection/"
      date = "2017-06-02 10:14:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "9b4971349ae85aa09c0a69852ed3e626c954954a3927b3d1b6646f139b930022"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\archer_lyl\\Release\\Archer_Input.pdb" ascii
      $s1 = "Archer_Input.dll" fullword ascii
      $s2 = "InstallArcherSvc" fullword ascii
      $s3 = "%s_%08X" fullword wide
      $s4 = "d\\\\.\\PhysicalDrive%d" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and ( $x1 or 3 of them )
}