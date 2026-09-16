rule sig_20161024_9c73a6307a01970e63b2e45834b5aac0 {
  meta:
    description = "datamaliciousorder - file 20161024_9c73a6307a01970e63b2e45834b5aac0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4db5c57cae90deef28940e4a38147b504ba7cf876ac954bdae284d7e456d8827"

  strings:
    $s1 = "} while (gv++ < mu0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}