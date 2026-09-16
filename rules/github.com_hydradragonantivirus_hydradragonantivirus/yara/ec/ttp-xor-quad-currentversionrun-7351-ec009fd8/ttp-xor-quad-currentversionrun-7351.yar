rule TTP_XOR_QUAD_CurrentVersionRun_7351 {
  strings:
    $key_7351 = { 20 3e [2] 04 30 [2] 2f 1c [2] 01 3e [2] 15 25 [2] 1a 3f [2] 04 22 [2] 06 23 [2] 1d 25 [2] 01 22 [2] 1d 0d }

  condition:
    any of them
}