rule Fireball_gubed_RID2C98 : APT DEMO EXE FILE T1546_012 {
   meta:
      description = "Detects Fireball malware - file gubed.exe"
      author = "Florian Roth"
      reference = "https://blog.checkpoint.com/research/fireball-chinese-malware-250-million-infection/"
      date = "2017-06-02 09:55:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      hash1 = "e3f69a1fb6fcaf9fd93386b6ba1d86731cd9e5648f7cff5242763188129cd158"
      tags = "APT, DEMO, EXE, FILE, T1546_012"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\MRT.exe" fullword wide
      $x2 = "tIphlpapi.dll" fullword wide
      $x3 = "http://%s/provide?clients=%s&reqs=visit.startload" fullword wide
      $x4 = "\\Gubed\\Release\\Gubed.pdb" ascii
      $x5 = "d2hrpnfyb3wv3k.cloudfront.net" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 1 of them )
}