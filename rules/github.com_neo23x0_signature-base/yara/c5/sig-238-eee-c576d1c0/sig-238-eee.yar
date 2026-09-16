rule sig_238_eee {
   meta:
      description = "Disclosed hacktool set (old stuff) - file eee.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "236916ce2980c359ff1d5001af6dacb99227d9cb"
      id = "9d3ad3a9-0498-5ca3-ac19-f250cb10c4d3"
   strings:
      $s0 = "szj1230@yesky.com" fullword wide
      $s3 = "C:\\Program Files\\DevStudio\\VB\\VB5.OLB" fullword ascii
      $s4 = "MailTo:szj1230@yesky.com" fullword wide
      $s5 = "Command1_Click" fullword ascii
      $s7 = "software\\microsoft\\internet explorer\\typedurls" fullword wide
      $s11 = "vb5chs.dll" fullword ascii
      $s12 = "MSVBVM50.DLL" fullword ascii
   condition:
      all of them
}