rule Turla_Mal_Script_Jan18_1_RID2FD7 : DEMO G0010 MAL RUSSIA SCRIPT T1059 {
   meta:
      description = "Detects Turla malicious script"
      author = "Florian Roth"
      reference = "https://ghostbin.com/paste/jsph7"
      date = "2018-01-19 12:14:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "180b920e9cea712d124ff41cd1060683a14a79285d960e17f0f49b969f15bfcc"
      tags = "DEMO, G0010, MAL, RUSSIA, SCRIPT, T1059"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".charCodeAt(i % " ascii
      $s2 = "{WScript.Quit();}" fullword ascii
      $s3 = ".charAt(i)) << 10) |" ascii
      $s4 = " = WScript.Arguments;var " ascii
      $s5 = "= \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\";var i;" ascii
   condition: 
      filesize < 200KB and 2 of them
}