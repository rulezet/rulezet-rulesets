rule sig_238_FPipe {
   meta:
      description = "Disclosed hacktool set (old stuff) - file FPipe.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "41d57d356098ff55fe0e1f0bcaa9317df5a2a45c"
      id = "0b2f11d9-a919-5790-8724-d2f028e4fa3a"
   strings:
      $s0 = "made to port 80 of the remote machine at 192.168.1.101 with the" fullword ascii
      $s1 = "Unable to resolve hostname \"%s\"" fullword ascii
      $s2 = "source port for that outbound connection being set to 53 also." fullword ascii
      $s3 = " -s    - outbound source port number" fullword ascii
      $s5 = "http://www.foundstone.com" fullword ascii
      $s20 = "Attempting to connect to %s port %d" fullword ascii
   condition:
      all of them
}