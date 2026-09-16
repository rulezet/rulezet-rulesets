rule sig_238_sqlcmd {
   meta:
      description = "Disclosed hacktool set (old stuff) - file sqlcmd.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 40
      hash = "b6e356ce6ca5b3c932fa6028d206b1085a2e1a9a"
      id = "0efdfac7-5a89-5251-b583-12b0a58c48ff"
   strings:
      $s0 = "Permission denial to EXEC command.:(" ascii
      $s3 = "by Eyas<cooleyas@21cn.com>" fullword ascii
      $s4 = "Connect to %s MSSQL server success.Enjoy the shell.^_^" fullword ascii
      $s5 = "Usage: %s <host> <uid> <pwd>" fullword ascii
      $s6 = "SqlCmd2.exe Inside Edition." fullword ascii
      $s7 = "Http://www.patching.net  2000/12/14" fullword ascii
      $s11 = "Example: %s 192.168.0.1 sa \"\"" fullword ascii
   condition:
      4 of them
}