rule Suspicious_JS_script_content {
   meta:
      description = "Detects suspicious statements in JavaScript files"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Research on Leviathan https://goo.gl/MZ7dRg"
      date = "2017-12-02"
      score = 70
      hash1 = "fc0fad39b461eb1cfc6be57932993fcea94fca650564271d1b74dd850c81602f"
      id = "6a547aa5-c58c-5559-9d3f-3f0d541eafd4"
   strings:
      $x1 = "new ActiveXObject('WScript.Shell')).Run('cmd /c " ascii
      $x2 = ".Run('regsvr32 /s /u /i:" ascii
      $x3 = "new ActiveXObject('WScript.Shell')).Run('regsvr32 /s" fullword ascii
      $x4 = "args='/s /u /i:" ascii
   condition:
      ( filesize < 10KB and 1 of them )
}