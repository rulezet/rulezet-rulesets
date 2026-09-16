rule TTP_XOR_QUAD_CurrentVersionRun_1b6b {
  strings:
    $key_1b6b = { 48 04 [2] 6c 0a [2] 47 26 [2] 69 04 [2] 7d 1f [2] 72 05 [2] 6c 18 [2] 6e 19 [2] 75 1f [2] 69 18 [2] 75 37 }

  condition:
    any of them
}