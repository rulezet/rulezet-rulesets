rule PowerShell_ISESteroids_Obfuscation {
   meta:
      description = "Detects PowerShell ISESteroids obfuscation"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/danielhbohannon/status/877953970437844993"
      date = "2017-06-23"
      id = "d686c4de-28fd-5d77-91d4-dde5661b75cd"
   strings:
      $x1 = "/\\/===\\__" ascii
      $x2 = "${__/\\/==" ascii
      $x3 = "Catch { }" fullword ascii
      $x4 = "\\_/=} ${_" ascii
   condition:
      2 of them
}