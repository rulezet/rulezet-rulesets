rule CVE_2017_8759_Mal_Doc_RID2D42 : CVE_2017_8759 DEMO EXPLOIT FILE MAL T1203 T1566_001 {
   meta:
      description = "Detects malicious files related to CVE-2017-8759 - file Doc1.doc"
      author = "Florian Roth"
      reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
      date = "2017-09-14 10:24:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-11-21"
      hash1 = "6314c5696af4c4b24c3a92b0e92a064aaf04fd56673e830f4d339b8805cc9635"
      tags = "CVE_2017_8759, DEMO, EXPLOIT, FILE, MAL, T1203, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "soap:wsdl=http://" ascii wide
      $s2 = "soap:wsdl=https://" ascii wide
      $s3 = "soap:wsdl=http%3" ascii wide
      $s4 = "soap:wsdl=https%3" ascii wide
      $c1 = "Project.ThisDocument.AutoOpen" fullword wide
   condition: 
      uint16 ( 0 ) == 0xcfd0 and filesize < 500KB and ( 1 of ( $s* ) and $c1 )
}