rule HKTL_CowTunnel_Dec25 {
   meta:
      description = "Detects CowTunnel Linux reverse-proxy tunnel (NSS wrapper + FRP client) used for outbound access/pivoting in React2Shell activity"
      author = "RussianPanda"
      date = "2025-12-08"
      score = 85
      reference = "https://www.huntress.com/blog/peerblight-linux-backdoor-exploits-react2shell"
      hash = "776850a1e6d6915e9bf35aa83554616129acd94e3a3f6673bd6ddaec530f4273"
   strings:
      $s1 = "cannot create proxy service, it should not happenned!"
      $s2 = "[nss] encrypt_data"
      $s3 = "[nss] decrypt_data"
   condition:
      uint32(0) == 0x464c457f and all of them
}