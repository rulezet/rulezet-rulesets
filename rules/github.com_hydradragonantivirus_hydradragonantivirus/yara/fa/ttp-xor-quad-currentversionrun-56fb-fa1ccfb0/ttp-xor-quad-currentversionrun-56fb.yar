rule TTP_XOR_QUAD_CurrentVersionRun_56fb {
  strings:
    $key_56fb = { 05 94 [2] 21 9a [2] 0a b6 [2] 24 94 [2] 30 8f [2] 3f 95 [2] 21 88 [2] 23 89 [2] 38 8f [2] 24 88 [2] 38 a7 }

  condition:
    any of them
}