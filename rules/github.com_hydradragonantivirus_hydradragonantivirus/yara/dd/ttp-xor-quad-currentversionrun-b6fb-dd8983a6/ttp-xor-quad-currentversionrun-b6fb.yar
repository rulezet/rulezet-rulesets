rule TTP_XOR_QUAD_CurrentVersionRun_b6fb {
  strings:
    $key_b6fb = { e5 94 [2] c1 9a [2] ea b6 [2] c4 94 [2] d0 8f [2] df 95 [2] c1 88 [2] c3 89 [2] d8 8f [2] c4 88 [2] d8 a7 }

  condition:
    any of them
}