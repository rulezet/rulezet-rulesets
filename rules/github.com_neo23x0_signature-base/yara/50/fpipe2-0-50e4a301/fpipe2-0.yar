rule FPipe2_0 {
   meta:
      description = "Disclosed hacktool set (old stuff) - file FPipe2.0.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "891609db7a6787575641154e7aab7757e74d837b"
      id = "7e104cf6-69d2-590e-8999-4f0d448719f2"
   strings:
      $s0 = "made to port 80 of the remote machine at 192.168.1.101 with the" fullword ascii
      $s1 = "Unable to resolve hostname \"%s\"" fullword ascii
      $s2 = " -s    - outbound connection source port number" fullword ascii
      $s3 = "source port for that outbound connection being set to 53 also." fullword ascii
      $s4 = "http://www.foundstone.com" fullword ascii
      $s19 = "FPipe" fullword ascii
   condition:
      all of them
}