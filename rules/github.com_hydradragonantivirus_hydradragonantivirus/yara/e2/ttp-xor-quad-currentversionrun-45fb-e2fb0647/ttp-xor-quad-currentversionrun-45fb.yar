rule TTP_XOR_QUAD_CurrentVersionRun_45fb {
  strings:
    $key_45fb = { 16 94 [2] 32 9a [2] 19 b6 [2] 37 94 [2] 23 8f [2] 2c 95 [2] 32 88 [2] 30 89 [2] 2b 8f [2] 37 88 [2] 2b a7 }

  condition:
    any of them
}