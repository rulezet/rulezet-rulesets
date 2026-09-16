rule TTP_XOR_QUAD_CurrentVersionRun_36fb {
  strings:
    $key_36fb = { 65 94 [2] 41 9a [2] 6a b6 [2] 44 94 [2] 50 8f [2] 5f 95 [2] 41 88 [2] 43 89 [2] 58 8f [2] 44 88 [2] 58 a7 }

  condition:
    any of them
}