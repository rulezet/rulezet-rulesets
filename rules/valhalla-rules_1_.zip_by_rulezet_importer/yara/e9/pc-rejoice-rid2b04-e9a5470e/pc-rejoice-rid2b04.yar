rule Pc_rejoice_RID2B04 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file rejoice.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 08:48:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "@members.3322.net/dyndns/update?system=dyndns&hostname=" fullword ascii
      $s2 = "http://www.xxx.com/xxx.exe" fullword ascii
      $s3 = "@ddns.oray.com/ph/update?hostname=" fullword ascii
      $s4 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
      $s5 = "ListViewProcessListColumnClick!" fullword ascii
      $s6 = "http://iframe.ip138.com/ic.asp" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and 3 of them
}