rule JS_Suspicious_MSHTA_Bypass_RID30F1 : DEMO SCRIPT T1059 T1059_007 T1218_005 {
   meta:
      description = "Detects MSHTA Bypass"
      author = "Florian Roth"
      reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
      date = "2017-07-19 13:01:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1059, T1059_007, T1218_005"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "mshtml,RunHTMLApplication" ascii
      $s2 = "new ActiveXObject(\"WScript.Shell\").Run(" ascii
      $s3 = "/c start mshta j" ascii nocase
   condition: 
      2 of them
}