rule sig_20161024_9f7302f416659eeb4f56c600f1725bc4 {
  meta:
    description = "datamaliciousorder - file 20161024_9f7302f416659eeb4f56c600f1725bc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fb2bcc257ce66f557db1642b6f168ac2e2b1c514ef6b93e560de00cb66f737a"

  strings:
    $s1 = "} while (cu++ < vr);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}