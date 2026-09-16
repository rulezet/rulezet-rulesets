rule EquationGroup_gr_dev_bin_now {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "f5ed8312fc6e624b04e1e2d6614f3c651c9e9902ff41f4d069c32caca0869fa4"
      id = "9ec19323-85d5-5edf-99eb-b452c09b870a"
   strings:
      $x1 = "HTTP_REFERER=\"https://127.0.0.1:6655/cgi/redmin?op=cron&action=once\"" fullword ascii
      $x2 = "exec /usr/share/redmin/cgi/redmin" fullword ascii
   condition:
      ( filesize < 1KB and 1 of them )
}