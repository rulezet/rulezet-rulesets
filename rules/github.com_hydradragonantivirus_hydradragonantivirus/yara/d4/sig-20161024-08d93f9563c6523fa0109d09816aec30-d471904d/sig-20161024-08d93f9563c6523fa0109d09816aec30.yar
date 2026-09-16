rule sig_20161024_08d93f9563c6523fa0109d09816aec30 {
  meta:
    description = "datamaliciousorder - file 20161024_08d93f9563c6523fa0109d09816aec30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75f7d274ec3503b661e5f10a1eaec6eef24be10466271d8524c917ea34f81336"

  strings:
    $s1 = "} while (tg++ < aq);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}