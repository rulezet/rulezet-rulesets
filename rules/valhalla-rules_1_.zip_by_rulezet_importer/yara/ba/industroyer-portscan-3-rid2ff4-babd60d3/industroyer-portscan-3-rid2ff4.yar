rule Industroyer_Portscan_3_RID2FF4 : APT DEMO EXE FILE {
   meta:
      description = "Detects Industroyer related custom port scaner"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2017/06/12/industroyer-biggest-threat-industrial-control-systems-since-stuxnet/"
      date = "2017-06-13 12:19:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "893e4cca7fe58191d2f6722b383b5e8009d3885b5913dcd2e3577e5a763cdb3f"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "!ZBfamily" fullword ascii
      $s2 = ":g/outddomo;" fullword ascii
      $s3 = "GHIJKLMNOTST" fullword ascii
      $d1 = "Error params Arguments!!!" fullword wide
      $d2 = "^(.+?.exe).*\\s+-ip\\s*=\\s*(.+)\\s+-ports\\s*=\\s*(.+)$" fullword wide
      $d3 = "Exhample:App.exe -ip= 127.0.0.1-100," fullword wide
      $d4 = "Error IP Range %ls - %ls" fullword wide
      $d5 = "Can't closesocket." fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 500KB and all of ( $s* ) or 2 of ( $d* ) )
}