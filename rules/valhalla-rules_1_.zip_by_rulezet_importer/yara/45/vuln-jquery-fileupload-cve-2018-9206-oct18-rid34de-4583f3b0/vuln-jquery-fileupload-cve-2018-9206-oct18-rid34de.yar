rule VULN_JQuery_FileUpload_CVE_2018_9206_Oct18_RID34DE : CVE_2018_9206 DEMO VULN {
   meta:
      description = "Detects JQuery File Upload vulnerability CVE-2018-9206"
      author = "Florian Roth"
      reference = "https://www.zdnet.com/article/zero-day-in-popular-jquery-plugin-actively-exploited-for-at-least-three-years/"
      date = "2018-10-19 15:48:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-11-15"
      tags = "CVE_2018_9206, DEMO, VULN"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "error_reporting(E_ALL | E_STRICT);" fullword ascii
      $s2 = "require('UploadHandler.php');" fullword ascii
      $s3 = "$upload_handler = new UploadHandler();" fullword ascii
   condition: 
      all of them
}