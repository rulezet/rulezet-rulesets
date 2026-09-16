rule Webshell_asp_EFSO_2_RID2E07 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file EFSO_2.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:57:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "%8@#@&P~,P,PP,MV~4BP^~,NS~m~PXc3,_PWbSPU W~~[u3Fffs~/%@#@&~~,PP~~,M!PmS,4S,mBPNB" 
   condition: 
      all of them
}