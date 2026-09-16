rule HKTL_BypassUacDll_6_RID2DDF : DEMO HKTL SUSP {
   meta:
      description = "Semiautomatically generated YARA rule - file BypassUacDll.aps"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 10:50:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "BypassUacDLL.dll" fullword wide
      $s4 = "AFX_IDP_COMMAND_FAILURE" fullword ascii
   condition: 
      all of them
}