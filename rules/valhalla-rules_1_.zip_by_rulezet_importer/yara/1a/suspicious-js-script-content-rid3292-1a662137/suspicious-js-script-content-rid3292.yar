rule Suspicious_JS_script_content_RID3292 : DEMO SCRIPT T1059 T1059_007 T1218_010 {
   meta:
      description = "Detects suspicious statements in JavaScript files"
      author = "Florian Roth"
      reference = "Research on Leviathan https://www.proofpoint.com/us/threat-insight/post/leviathan-espionage-actor-spearphishes-maritime-and-defense-targets"
      date = "2017-12-02 14:10:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "fc0fad39b461eb1cfc6be57932993fcea94fca650564271d1b74dd850c81602f"
      tags = "DEMO, SCRIPT, T1059, T1059_007, T1218_010"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "new ActiveXObject('WScript.Shell')).Run('cmd /c " ascii
      $x2 = ".Run('regsvr32 /s /u /i:" ascii
      $x3 = "new ActiveXObject('WScript.Shell')).Run('regsvr32 /s" fullword ascii
      $x4 = "args='/s /u /i:" ascii
   condition: 
      ( filesize < 10KB and 1 of them )
}