rule WiltedTulip_WindowsTask_RID3065 : APT DEMO {
   meta:
      description = "Detects hack tool used in Operation Wilted Tulip - Windows Tasks"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23 12:38:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c3cbe88b82cd0ea46868fb4f2e8ed226f3419fc6d4d6b5f7561e70f4cd33822c"
      hash2 = "340cbbffbb7685133fc318fa20e4620ddf15e56c0e65d4cf1b2d606790d4425d"
      hash3 = "b6f515b3f713b70b808fc6578232901ffdeadeb419c9c4219fbfba417bba9f01"
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "<Command>C:\\Windows\\svchost.exe</Command>" fullword wide
      $x2 = "<Arguments>-nop -w hidden -encodedcommand" wide
      $x3 = "-encodedcommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgA" 
   condition: 
      1 of them
}