rule Netview_Hacktool_Output {
   meta:
      description = "Network domain enumeration tool output - often used by attackers - file filename.txt"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/mubix/netview"
      date = "2016-03-07"
      score = 60
      id = "259db870-6293-5a55-b56a-f981c060c18f"
   strings:
      $s1 = "[*] Using interval:" fullword
      $s2 = "[*] Using jitter:" fullword
      $s3 = "[+] Number of hosts:" fullword
   condition:
      2 of them
}