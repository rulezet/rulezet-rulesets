rule TTP_XOR_QUAD_CurrentVersionRun_196b {
  strings:
    $key_196b = { 4a 04 [2] 6e 0a [2] 45 26 [2] 6b 04 [2] 7f 1f [2] 70 05 [2] 6e 18 [2] 6c 19 [2] 77 1f [2] 6b 18 [2] 77 37 }

  condition:
    any of them
}