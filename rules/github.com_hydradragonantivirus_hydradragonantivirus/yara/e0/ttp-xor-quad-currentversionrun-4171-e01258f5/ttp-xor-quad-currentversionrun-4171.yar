rule TTP_XOR_QUAD_CurrentVersionRun_4171 {
  strings:
    $key_4171 = { 12 1e [2] 36 10 [2] 1d 3c [2] 33 1e [2] 27 05 [2] 28 1f [2] 36 02 [2] 34 03 [2] 2f 05 [2] 33 02 [2] 2f 2d }

  condition:
    any of them
}