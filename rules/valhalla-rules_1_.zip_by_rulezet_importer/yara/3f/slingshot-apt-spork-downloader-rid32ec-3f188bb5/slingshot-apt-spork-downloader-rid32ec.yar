rule Slingshot_APT_Spork_Downloader_RID32EC : APT DEMO EXE FILE {
   meta:
      description = "Detects malware from Slingshot APT"
      author = "Florian Roth"
      reference = "https://securelist.com/apt-slingshot/84312/"
      date = "2018-03-09 14:25:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Usage: spork -c IP:PORT" fullword ascii wide
      $s2 = "connect-back IP address and port number" 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and 1 of them
}