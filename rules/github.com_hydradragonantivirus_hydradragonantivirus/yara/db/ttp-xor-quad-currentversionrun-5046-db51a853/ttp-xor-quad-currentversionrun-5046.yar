rule TTP_XOR_QUAD_CurrentVersionRun_5046 {
  strings:
    $key_5046 = { 03 29 [2] 27 27 [2] 0c 0b [2] 22 29 [2] 36 32 [2] 39 28 [2] 27 35 [2] 25 34 [2] 3e 32 [2] 22 35 [2] 3e 1a }

  condition:
    any of them
}