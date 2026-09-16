rule sig_238_xsniff {
   meta:
      description = "Disclosed hacktool set (old stuff) - file xsniff.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "d61d7329ac74f66245a92c4505a327c85875c577"
      id = "1e61a732-8691-5f84-beb0-c9f7e6d46538"
   strings:
      $s2 = "xsiff.exe -pass -hide -log pass.log" fullword ascii
      $s3 = "%s - simple sniffer for win2000" fullword ascii
      $s4 = "xsiff.exe -tcp -udp -asc -addr 192.168.1.1" fullword ascii
      $s5 = "HOST: %s USER: %s, PASS: %s" fullword ascii
      $s7 = "http://www.xfocus.org" fullword ascii
      $s9 = "  -pass        : Filter username/password" fullword ascii
      $s18 = "  -udp         : Output udp packets" fullword ascii
      $s19 = "Code by glacier <glacier@xfocus.org>" fullword ascii
      $s20 = "  -tcp         : Output tcp packets" fullword ascii
   condition:
      6 of them
}