rule TTP_XOR_QUAD_CurrentVersionRun_766a {
  strings:
    $key_766a = { 25 05 [2] 01 0b [2] 2a 27 [2] 04 05 [2] 10 1e [2] 1f 04 [2] 01 19 [2] 03 18 [2] 18 1e [2] 04 19 [2] 18 36 }

  condition:
    any of them
}