rule sig_238_gina {
   meta:
      description = "Disclosed hacktool set (old stuff) - file gina.reg"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "324acc52566baf4afdb0f3e4aaf76e42899e0cf6"
      id = "85c19493-e6d4-55e8-8526-6817243e90cf"
   strings:
      $s0 = "\"gina\"=\"gina.dll\"" fullword ascii
      $s1 = "REGEDIT4" fullword ascii
      $s2 = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon]" fullword ascii
   condition:
      all of them
}