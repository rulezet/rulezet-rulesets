rule MAL_HawkEye_Keylogger_Gen_Dec18_RID324D : DEMO GEN MAL T1056_001 T1113 {
   meta:
      description = "Detects HawkEye Keylogger Reborn"
      author = "Florian Roth"
      reference = "https://twitter.com/James_inthe_box/status/1072116224652324870"
      date = "2018-12-10 13:59:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b8693e015660d7bd791356b352789b43bf932793457d54beae351cf7a3de4dad"
      tags = "DEMO, GEN, MAL, T1056_001, T1113"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "HawkEye Keylogger" fullword wide
      $s2 = "_ScreenshotLogger" ascii
      $s3 = "_PasswordStealer" ascii
   condition: 
      2 of them
}