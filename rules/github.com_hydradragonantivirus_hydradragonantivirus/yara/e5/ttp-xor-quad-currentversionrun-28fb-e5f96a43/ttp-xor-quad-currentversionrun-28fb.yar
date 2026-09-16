rule TTP_XOR_QUAD_CurrentVersionRun_28fb {
  strings:
    $key_28fb = { 7b 94 [2] 5f 9a [2] 74 b6 [2] 5a 94 [2] 4e 8f [2] 41 95 [2] 5f 88 [2] 5d 89 [2] 46 8f [2] 5a 88 [2] 46 a7 }

  condition:
    any of them
}