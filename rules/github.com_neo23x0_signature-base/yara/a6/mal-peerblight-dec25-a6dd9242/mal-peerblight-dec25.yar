rule MAL_PeerBlight_Dec25 {
   meta:
      description = "Detects PeerBlight Linux backdoor with systemd persistence artifacts and user-mode masquerading strings, linked to React2Shell exploitation"
      author = "RussianPanda"
      date = "2025-12-07"
      score = 85
      reference = "https://www.huntress.com/blog/peerblight-linux-backdoor-exploits-react2shell"
      hash = "a605a70d031577c83c093803d11ec7c1e29d2ad530f8e95d9a729c3818c7050d"
   strings:
      $s1 = "/bin/systemd-daemon"
      $s2 = "/lib/systemd/system/systemd-agent.service"
      $s3 = "group"
      $s4 = "tag"
      $s5 = "arch"
      $s6 = "softirq"
   condition:
      uint32(0) == 0x464c457f and 5 of them
}