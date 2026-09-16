rule Ncat_Hacktools_CN {
   meta:
      description = "Disclosed hacktool set - file nc.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "17.11.14"
      score = 60
      hash = "001c0c01c96fa56216159f83f6f298755366e528"
      id = "bdbfaf75-f8c0-508e-b6b1-9ddea179a325"
   strings:
      $s0 = "nc -l -p port [options] [hostname] [port]" fullword ascii
      $s2 = "nc [-options] hostname port[s] [ports] ... " fullword ascii
      $s3 = "gethostpoop fuxored" fullword ascii
      $s6 = "VERNOTSUPPORTED" fullword ascii
      $s7 = "%s [%s] %d (%s)" fullword ascii
      $s12 = " `--%s' doesn't allow an argument" fullword ascii
   condition:
      all of them
}