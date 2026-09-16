rule HKTL_peek_a_boo_RID2CA7 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file peek-a-boo.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:58:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "__vbaHresultCheckObj" 
      $s1 = "\\VB\\VB5.OLB" 
      $s2 = "capGetDriverDescriptionA" 
      $s3 = "__vbaExceptHandler" 
      $s4 = "EVENT_SINK_Release" 
      $s8 = "__vbaErrorOverflow" 
   condition: 
      all of them
}