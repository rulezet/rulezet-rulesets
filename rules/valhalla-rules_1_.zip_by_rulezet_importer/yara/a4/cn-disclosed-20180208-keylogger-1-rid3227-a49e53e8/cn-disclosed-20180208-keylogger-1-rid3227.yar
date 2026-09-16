rule CN_disclosed_20180208_KeyLogger_1_RID3227 : CHINA DEMO EXE FILE MAL T1056_001 {
   meta:
      description = "Detects malware from disclosed CN malware set"
      author = "Florian Roth"
      reference = "https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details"
      date = "2018-02-08 13:53:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c492889e1d271a98e15264acbb21bfca9795466882520d55dc714c4899ed2fcf"
      tags = "CHINA, DEMO, EXE, FILE, MAL, T1056_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x2 = "Process already elevated." fullword wide
      $x3 = "GetKeyloggErLogsResponse" fullword ascii
      $x4 = "get_encryptedPassword" fullword ascii
      $x5 = "DoDownloadAndExecute" fullword ascii
      $x6 = "GetKeyloggeRLogs" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and 2 of them
}