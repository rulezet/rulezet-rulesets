rule DeepPanda_sl_txt_packed_RID3037 : APT CHINA DEMO G0009 T1027_002 {
   meta:
      description = "Hack Deep Panda - FBI Liaison Alert System # A-000049-MW - ScanLine sl-txt-packed"
      author = "Florian Roth"
      reference = "http://krebsonsecurity.com/wp-content/uploads/2015/02/FBI-Flash-Warning-Deep-Panda.pdf"
      date = "2015-02-08 12:30:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, CHINA, DEMO, G0009, T1027_002"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Command line port scanner" fullword wide
      $s1 = "sl.exe" fullword wide
      $s2 = "CPports.txt" fullword ascii
      $s3 = ",GET / HTTP/.}" fullword ascii
      $s4 = "Foundstone Inc." fullword wide
      $s9 = " 2002 Foundstone Inc." fullword wide
      $s15 = ", Inc. 2002" fullword ascii
      $s20 = "ICMP Time" fullword ascii
   condition: 
      all of them
}