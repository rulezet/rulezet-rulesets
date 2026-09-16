rule WannCry_m_vbs_RID2C49 : CRIME DEMO FILE MAL RANSOM SCRIPT {
   meta:
      description = "Detects WannaCry Ransomware VBS"
      author = "Florian Roth"
      reference = "https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100"
      date = "2017-05-12 09:42:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "51432d3196d9b78bdc9867a77d601caffd4adaa66dcac944a5ba0b3112bbea3b"
      tags = "CRIME, DEMO, FILE, MAL, RANSOM, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = ".TargetPath = \"C:\\@" ascii
      $x2 = ".CreateShortcut(\"C:\\@" ascii
      $s3 = " = WScript.CreateObject(\"WScript.Shell\")" ascii
   condition: 
      ( uint16 ( 0 ) == 0x4553 and filesize < 1KB and all of them )
}