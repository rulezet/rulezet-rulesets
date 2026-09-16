rule TTP_XOR_QUAD_CurrentVersionRun_e347 {
  strings:
    $key_e347 = { b0 28 [2] 94 26 [2] bf 0a [2] 91 28 [2] 85 33 [2] 8a 29 [2] 94 34 [2] 96 35 [2] 8d 33 [2] 91 34 [2] 8d 1b }

  condition:
    any of them
}