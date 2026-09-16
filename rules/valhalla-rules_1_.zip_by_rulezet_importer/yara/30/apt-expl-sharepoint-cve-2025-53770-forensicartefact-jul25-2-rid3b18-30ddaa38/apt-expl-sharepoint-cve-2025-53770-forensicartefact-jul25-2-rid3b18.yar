rule APT_EXPL_Sharepoint_CVE_2025_53770_ForensicArtefact_Jul25_2_RID3B18 : APT CVE_2025_53770 DEMO EXPLOIT {
   meta:
      description = "Detects URIs accessed during the exploitation of SharePoint RCE vulnerability CVE-2025-53770"
      author = "Florian Roth"
      reference = "https://research.eye.security/sharepoint-under-siege/"
      date = "2025-07-20 20:14:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-07-24"
      tags = "APT, CVE_2025_53770, DEMO, EXPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "-EncodedCommand JABiAGEAcwBlADYANABTAHQAcgBpAG4AZwAgAD0" ascii wide
      $x2 = "TEMPLATE\\LAYOUTS\\spinstall" ascii wide
      $x3 = "TEMPLATE\\LAYOUTS\\ghostfile" ascii wide
      $x4 = "TEMPLATE\\LAYOUTS\\1.css" ascii wide
      $x5 = "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:120.0)+Gecko/20100101+Firefox/120.0 /_layouts/SignOut.aspx" ascii wide
      $xe1 = "TQBJAEMAUgBPAFMAfgAxAFwAVwBFAEIAUwBFAFIAfgAxAFwAMQA2AFwAVABFAE0AUABMAEEAVABFAFwATABBAFkATwBVAFQAUwBcA" 
      $xe2 = "0ASQBDAFIATwBTAH4AMQBcAFcARQBCAFMARQBSAH4AMQBcADEANgBcAFQARQBNAFAATABBAFQARQBcAEwAQQBZAE8AVQBUAFMAXA" 
      $xe3 = "NAEkAQwBSAE8AUwB+ADEAXABXAEUAQgBTAEUAUgB+ADEAXAAxADYAXABUAEUATQBQAEwAQQBUAEUAXABMAEEAWQBPAFUAVABTAFwA" 
      $xe4 = "TQBJAEMAUgBPAFMAfgAxAFwAVwBFAEIAUwBFAFIAfgAxAFwAMQA1AFwAVABFAE0AUABMAEEAVABFAFwATABBAFkATwBVAFQAUwBcA" 
      $xe5 = "0ASQBDAFIATwBTAH4AMQBcAFcARQBCAFMARQBSAH4AMQBcADEANQBcAFQARQBNAFAATABBAFQARQBcAEwAQQBZAE8AVQBUAFMAXA" 
      $xe6 = "NAEkAQwBSAE8AUwB+ADEAXABXAEUAQgBTAEUAUgB+ADEAXAAxADUAXABUAEUATQBQAEwAQQBUAEUAXABMAEEAWQBPAFUAVABTAFwA" 
   condition: 
      1 of them
}