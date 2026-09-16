rule MAL_PHP_EFile_Apr23_1_RID2DCD : DEMO MAL {
   meta:
      description = "Detects malware "
      author = "Florian Roth"
      reference = "https://twitter.com/malwrhunterteam/status/1642988428080865281?s=12&t=C0_T_re0wRP_NfKa27Xw9w"
      date = "2023-04-06 10:47:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )" ascii
      $s2 = "C:\\\\ProgramData\\\\Browsers" ascii fullword
      $s3 = "curl_https($api_url." ascii
   condition: 
      all of them
}