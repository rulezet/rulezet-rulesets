rule SUSP_XORed_Mozilla_Oct19 {
   meta:
      old_rule_name = "SUSP_XORed_Mozilla"
      description = "Detects suspicious single byte XORed keyword 'Mozilla/5.0' - it uses yara's XOR modifier and therefore cannot print the XOR key. You can use the CyberChef recipe linked in the reference field to brute force the used key."
      author = "Florian Roth"
      reference = "https://gchq.github.io/CyberChef/#recipe=XOR_Brute_Force()"
      date = "2019-10-28"
      modified = "2023-11-03"
      score = 60
      id = "71e5b399-c384-5330-ae52-4e0a806e7969"
   strings:
      $xo1 = "Mozilla/5.0" xor ascii wide
      $xof1 = "Mozilla/5.0" ascii wide

      $fpa1 = "Sentinel Labs" wide
      $fpa2 = "<filter object at" ascii 

      $fpb1 = { 64 65 78 0a 30 33 35 } 
   condition:
      $xo1 
      and not $xof1 
      and not 1 of ($fpa*)
      and not $fpb1 at 0
}