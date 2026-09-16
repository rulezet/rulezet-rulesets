rule Webshell_C99_Shell_ci_Biz_RID3061 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:37:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f2fa878de03732fbf5c86d656467ff50"
      hash2 = "27786d1e0b1046a1a7f67ee41c64bf4c"
      hash3 = "0f5b9238d281bc6ac13406bb24ac2a5b"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s8 = "else {echo \"Running datapipe... ok! Connect to <b>\".getenv(\"SERVER_ADDR\"" 
   condition: 
      all of them
}