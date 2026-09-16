rule TTP_XOR_QUAD_CurrentVersionRun_47fb {
  strings:
    $key_47fb = { 14 94 [2] 30 9a [2] 1b b6 [2] 35 94 [2] 21 8f [2] 2e 95 [2] 30 88 [2] 32 89 [2] 29 8f [2] 35 88 [2] 29 a7 }

  condition:
    any of them
}