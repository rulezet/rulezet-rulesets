rule LinuxHacktool_eyes_pscan2 {
   meta:
      description = "Linux hack tools - file pscan2"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "not set"
      date = "2015/01/19"
      hash = "56b476cba702a4423a2d805a412cae8ef4330905"
      id = "02d96766-6696-5410-ad48-bd8cb642ac51"
   strings:
      $s0 = "# pscan completed in %u seconds. (found %d ips)" fullword ascii
      $s1 = "Usage: %s <b-block> <port> [c-block]" fullword ascii
      $s3 = "%s.%d.* (total: %d) (%.1f%% done)" fullword ascii
      $s8 = "Invalid IP." fullword ascii
      $s9 = "# scanning: " fullword ascii
      $s10 = "Unable to allocate socket." fullword ascii
   condition:
      2 of them
}