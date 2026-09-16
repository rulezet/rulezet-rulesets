rule TTP_XOR_QUAD_CurrentVersionRun_46fb {
  strings:
    $key_46fb = { 15 94 [2] 31 9a [2] 1a b6 [2] 34 94 [2] 20 8f [2] 2f 95 [2] 31 88 [2] 33 89 [2] 28 8f [2] 34 88 [2] 28 a7 }

  condition:
    any of them
}