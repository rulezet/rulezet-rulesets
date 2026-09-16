rule HKTL_HYTop_CaseSwitch_2005_RID2FEA : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2005.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:17:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "MSComDlg.CommonDialog" 
      $s2 = "CommonDialog1" 
      $s3 = "__vbaExceptHandler" 
      $s4 = "EVENT_SINK_Release" 
      $s5 = "EVENT_SINK_AddRef" 
      $s6 = "By Marcos" 
      $s7 = "EVENT_SINK_QueryInterface" 
      $s8 = "MethCallEngine" 
   condition: 
      all of them
}