rule TTP_XOR_QUAD_CurrentVersionRun_57fb {
  strings:
    $key_57fb = { 04 94 [2] 20 9a [2] 0b b6 [2] 25 94 [2] 31 8f [2] 3e 95 [2] 20 88 [2] 22 89 [2] 39 8f [2] 25 88 [2] 39 a7 }

  condition:
    any of them
}