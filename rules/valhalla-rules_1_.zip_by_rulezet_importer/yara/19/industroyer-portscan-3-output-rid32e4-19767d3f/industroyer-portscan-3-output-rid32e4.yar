rule Industroyer_Portscan_3_Output_RID32E4 : APT DEMO {
   meta:
      description = "Detects Industroyer related custom port scaner output file"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2017/06/12/industroyer-biggest-threat-industrial-control-systems-since-stuxnet/"
      date = "2017-06-13 14:24:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "WSA library load complite." fullword ascii
      $s2 = "Connection refused" fullword ascii
   condition: 
      all of them
}