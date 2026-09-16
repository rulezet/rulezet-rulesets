rule Webshell_DarkBlade1_3_asp_indexx_RID3355 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file indexx.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:43:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "Const strs_toTransform=\"command|Radmin|NTAuThenabled|FilterIp|IISSample|PageCou" 
   condition: 
      all of them
}