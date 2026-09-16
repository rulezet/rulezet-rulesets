rule EXPL_SUSP_JS_POC_RSC_Detector_Payloads_Dec25_RID367F : CVE_2025_55182 DEMO EXPLOIT SUSP T1059_007 {
   meta:
      description = "Detects RCE indicators related to the proof-of-concept code for the React Server Remote Code Execution Vulnerability (CVE-2025-55182) as used in the RSC Detector browser extension but could be used in other JavaScript based PoC code as well"
      author = "Florian Roth"
      reference = "https://github.com/mrknow001/RSC_Detector"
      date = "2025-12-06 16:58:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2025_55182, DEMO, EXPLOIT, SUSP, T1059_007"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "process.mainModule.require('child_process').execSync(" 
      $s2 = ").toString('base64');" 
      $f1 = "echo vulnerability_test" 
   condition: 
      all of ( $s* ) and not 1 of ( $f* )
}