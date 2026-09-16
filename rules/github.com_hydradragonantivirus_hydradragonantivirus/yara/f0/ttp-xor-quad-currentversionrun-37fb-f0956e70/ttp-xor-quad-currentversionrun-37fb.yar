rule TTP_XOR_QUAD_CurrentVersionRun_37fb {
  strings:
    $key_37fb = { 64 94 [2] 40 9a [2] 6b b6 [2] 45 94 [2] 51 8f [2] 5e 95 [2] 40 88 [2] 42 89 [2] 59 8f [2] 45 88 [2] 59 a7 }

  condition:
    any of them
}