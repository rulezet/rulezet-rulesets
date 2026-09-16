rule TSCookie {
          meta:
            description = "detect TSCookie in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "https://blogs.jpcert.or.jp/en/2018/03/malware-tscooki-7aa0.html"
            hash1 = "6d2f5675630d0dae65a796ac624fb90f42f35fbe5dec2ec8f4adce5ebfaabf75"

          strings:
            $v1 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" wide
            $b1 = { 68 D4 08 00 00 }

          condition: all of them
}