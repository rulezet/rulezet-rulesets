rule sekurlsa_RID2A7B : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file sekurlsa_RID2A7B.dll"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 06:16:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Bienvenue dans un processus distant" fullword wide
      $s2 = "Format d'appel invalide : addLogonSession [idSecAppHigh] idSecAppLow Utilisateur" wide
      $s3 = "SECURITY\\Policy\\Secrets" fullword wide
      $s4 = "Injection de donn" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1150KB and all of them
}