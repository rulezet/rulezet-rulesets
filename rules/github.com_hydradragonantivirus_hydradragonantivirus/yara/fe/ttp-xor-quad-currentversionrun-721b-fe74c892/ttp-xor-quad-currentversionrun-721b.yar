rule TTP_XOR_QUAD_CurrentVersionRun_721b {
  strings:
    $key_721b = { 21 74 [2] 05 7a [2] 2e 56 [2] 00 74 [2] 14 6f [2] 1b 75 [2] 05 68 [2] 07 69 [2] 1c 6f [2] 00 68 [2] 1c 47 }

  condition:
    any of them
}