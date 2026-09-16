rule TTP_XOR_QUAD_CurrentVersionRun_60fb {
  strings:
    $key_60fb = { 33 94 [2] 17 9a [2] 3c b6 [2] 12 94 [2] 06 8f [2] 09 95 [2] 17 88 [2] 15 89 [2] 0e 8f [2] 12 88 [2] 0e a7 }

  condition:
    any of them
}