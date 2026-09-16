rule TTP_XOR_QUAD_CurrentVersionRun_71fb {
  strings:
    $key_71fb = { 22 94 [2] 06 9a [2] 2d b6 [2] 03 94 [2] 17 8f [2] 18 95 [2] 06 88 [2] 04 89 [2] 1f 8f [2] 03 88 [2] 1f a7 }

  condition:
    any of them
}