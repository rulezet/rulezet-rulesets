rule SUSP_OBFUSC_JS_Sept21_2_RID2E68 : DEMO G0046 OBFUS RUSSIA SUSP T1027 T1059_007 {
   meta:
      description = "Detects JavaScript obfuscation as used in MalDocs by FIN7 group"
      author = "Florian Roth"
      reference = "https://www.anomali.com/blog/cybercrime-group-fin7-using-windows-11-alpha-themed-docs-to-drop-javascript-backdoor"
      date = "2021-09-07 11:13:11"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, G0046, OBFUS, RUSSIA, SUSP, T1027, T1059_007"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "=new RegExp(String.fromCharCode(" ascii
      $s2 = ".charCodeAt(" ascii
      $s3 = ".substr(0, " ascii
      $s4 = "var shell = new ActiveXObject(" ascii
      $s5 = "= new Date().getUTCMilliseconds();" ascii
      $s6 = ".deleteFile(WScript.ScriptFullName);" ascii
   condition: 
      filesize < 6000KB and ( 4 of them )
}