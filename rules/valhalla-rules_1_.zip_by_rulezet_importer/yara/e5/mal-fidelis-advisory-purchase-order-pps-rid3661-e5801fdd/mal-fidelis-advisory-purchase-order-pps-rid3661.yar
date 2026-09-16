rule MAL_Fidelis_Advisory_Purchase_Order_pps_RID3661 : DEMO MAL {
   meta:
      description = "Detects a string found in a malicious document named Purchase_Order.pps"
      author = "Florian Roth"
      reference = "http://www.fidelissecurity.com/sites/default/files/FTA_1017_Phishing_in_Plain_Sight-Body-FINAL.pdf"
      date = "2015-06-09 16:53:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "DEMO, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Users\\Gozie\\Desktop\\Purchase-Order.gif" ascii
   condition: 
      all of them
}