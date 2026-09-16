rule EXPL_SUSP_JS_POC_RSC_Detector_Payloads_Dec25 {
   meta:
      description = "Detects RCE indicators related to the proof-of-concept code for the React Server Remote Code Execution Vulnerability (CVE-2025-55182) as used in the RSC Detector browser extension but could be used in other JavaScript based PoC code as well"
      author = "Florian Roth"
      reference = "https://github.com/mrknow001/RSC_Detector"
      date = "2025-12-06"
      score = 70
   strings:
      $s1 = "process.mainModule.require('child_process').execSync("
      $s2 = ").toString('base64');"

            $f1 = "echo vulnerability_test"
   condition:
      all of ($s*)
      and not 1 of ($f*)
}