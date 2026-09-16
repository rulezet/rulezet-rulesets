rule WannCry_BAT_RID2B09 : CRIME DEMO FILE MAL RANSOM SCRIPT {
   meta:
      description = "Detects WannaCry Ransomware BATCH File"
      author = "Florian Roth"
      reference = "https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100"
      date = "2017-05-12 08:49:21"
      score = 100
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "f01b7f52e3cb64f01ddc248eb6ae871775ef7cb4297eba5d230d0345af9a5077"
      tags = "CRIME, DEMO, FILE, MAL, RANSOM, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "@.exe\">> m.vbs" ascii
      $s2 = "cscript.exe //nologo m.vbs" fullword ascii
      $s3 = "echo SET ow = WScript.CreateObject(\"WScript.Shell\")> " ascii
      $s4 = "echo om.Save>> m.vbs" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x6540 and filesize < 1KB and 1 of them )
}