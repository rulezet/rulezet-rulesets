rule sig_20161024_5093cc6fe08912aab52793df89403d76 {
  meta:
    description = "datamaliciousorder - file 20161024_5093cc6fe08912aab52793df89403d76.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab8567eb89ad9da4608557c8fe5b980e122f46cb01650333c75f4204a2f7da9a"

  strings:
    $s1 = "} while (xk++ < yr0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}