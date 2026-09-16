rule CN_Portscan: APT {
   meta:
      description = "CN Port Scanner"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "2013-11-29"
      confidential = false
      score = 70
      id = "fb52a89a-2270-5170-9874-9278a0177454"
   strings:
      $s2 = "TCP 12.12.12.12"
   condition:
      uint16(0) == 0x5A4D and $s2
}