rule TTP_XOR_QUAD_CurrentVersionRun_27fb {
  strings:
    $key_27fb = { 74 94 [2] 50 9a [2] 7b b6 [2] 55 94 [2] 41 8f [2] 4e 95 [2] 50 88 [2] 52 89 [2] 49 8f [2] 55 88 [2] 49 a7 }

  condition:
    any of them
}