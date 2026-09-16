import "pe"
rule CN_disclosed_20180208_Mal4_RID2F5C : CHINA DEMO EXE FILE MAL {
   meta:
      description = "Detects malware from disclosed CN malware set"
      author = "Florian Roth"
      reference = "https://www.virustotal.com/graph/#/selected/n120z79z208z189/drawer/graph-details"
      date = "2018-02-08 11:53:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f7549c74f09be7e4dbfb64006e535b9f6d17352e236edc2cdb102ec3035cf66e"
      tags = "CHINA, DEMO, EXE, FILE, MAL"
      required_modules = "pe"
      minimum_yara = "3.6.0"
      
   strings:
      $s1 = "Microsoft .Net Framework COM+ Support" fullword ascii
      $s2 = "Microsoft .NET and Windows XP COM+ Integration with SOAP" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and 1 of them and pe.exports ( "SPACE" )
}