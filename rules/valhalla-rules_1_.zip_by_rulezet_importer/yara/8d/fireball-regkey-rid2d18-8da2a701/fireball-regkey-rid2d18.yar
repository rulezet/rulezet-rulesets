rule Fireball_regkey_RID2D18 : APT DEMO EXE FILE T1113 {
   meta:
      description = "Detects Fireball malware - file regkey.exe"
      author = "Florian Roth"
      reference = "https://blog.checkpoint.com/research/fireball-chinese-malware-250-million-infection/"
      date = "2017-06-02 10:17:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "fff2818caa9040486a634896f329b8aebaec9121bdf9982841f0646763a1686b"
      tags = "APT, DEMO, EXE, FILE, T1113"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\WinMain\\Release\\WinMain.pdb" ascii
      $s2 = "ScreenShot" fullword wide
      $s3 = "WINMAIN" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}