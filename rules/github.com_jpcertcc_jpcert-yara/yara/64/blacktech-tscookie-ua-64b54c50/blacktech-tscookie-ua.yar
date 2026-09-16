rule BlackTech_TSCookie_UA {
    meta:
      description = "detect TSCookie in memory"
      author = "JPCERT/CC Incident Response Group"
      rule_usage = "memory scan"
      reference = "https://blogs.jpcert.or.jp/en/2018/03/malware-tscooki-7aa0.html"
      hash1 = "6d2f5675630d0dae65a796ac624fb90f42f35fbe5dec2ec8f4adce5ebfaabf75"

    strings:
      $v1 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" wide
      $b1 = { 68 D4 08 00 00 }
      $d1 = { 68 78 0B 00 00 }
      $v1b = { 68 9C 95 1A 6E }
      $v1c = { 68 E6 17 8F 7B }
      $v1d = { C7 40 7C 92 5A 76 5D }
      $v1e = { C7 ?? ?? ?? ?? ?? 92 5A 76 5D }

    condition:
      ($v1 and ($b1 or $d1)) or ($v1b and $v1c and ($v1d or $v1e))
}