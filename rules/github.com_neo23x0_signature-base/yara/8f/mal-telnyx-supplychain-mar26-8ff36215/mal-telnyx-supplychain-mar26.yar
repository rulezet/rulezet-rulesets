rule MAL_Telnyx_SupplyChain_Mar26 {
   meta:
      description = "Detects malicious indicators used in Telnyx supply chain attack"
      author = "Marius Benthin"
      date = "2026-03-28"
      reference = "https://www.aikido.dev/blog/telnyx-pypi-compromised-teampcp-canisterworm"
      hash = "ab4c4aebb52027bf3d2f6b2dcef593a1a2cff415774ea4711f7d6e0aa1451d4e"
      score = 80
      id = "73d9c3d4-7274-5278-aea3-7e921bf5d0b2"
   strings:
      $s1 = "bXNidWlsZC5leGU="        $s2 = "TW96aWxsY"        $s3 = ".getnframes("        $s4 = "exec(base64.b64decode("
   condition:
      filesize < 500KB
      and 3 of them
}