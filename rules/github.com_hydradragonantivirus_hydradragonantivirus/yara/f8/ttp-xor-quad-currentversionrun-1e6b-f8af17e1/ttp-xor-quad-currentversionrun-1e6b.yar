rule TTP_XOR_QUAD_CurrentVersionRun_1e6b {
  strings:
    $key_1e6b = { 4d 04 [2] 69 0a [2] 42 26 [2] 6c 04 [2] 78 1f [2] 77 05 [2] 69 18 [2] 6b 19 [2] 70 1f [2] 6c 18 [2] 70 37 }

  condition:
    any of them
}