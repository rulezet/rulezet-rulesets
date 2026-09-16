rule TTP_XOR_QUAD_CurrentVersionRun_44fb {
  strings:
    $key_44fb = { 17 94 [2] 33 9a [2] 18 b6 [2] 36 94 [2] 22 8f [2] 2d 95 [2] 33 88 [2] 31 89 [2] 2a 8f [2] 36 88 [2] 2a a7 }

  condition:
    any of them
}