rule TTP_XOR_QUAD_CurrentVersionRun_215b {
  strings:
    $key_215b = { 72 34 [2] 56 3a [2] 7d 16 [2] 53 34 [2] 47 2f [2] 48 35 [2] 56 28 [2] 54 29 [2] 4f 2f [2] 53 28 [2] 4f 07 }

  condition:
    any of them
}