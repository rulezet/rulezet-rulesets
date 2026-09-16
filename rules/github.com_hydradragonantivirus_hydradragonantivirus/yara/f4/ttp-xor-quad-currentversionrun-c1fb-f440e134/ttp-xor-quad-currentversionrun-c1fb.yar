rule TTP_XOR_QUAD_CurrentVersionRun_c1fb {
  strings:
    $key_c1fb = { 92 94 [2] b6 9a [2] 9d b6 [2] b3 94 [2] a7 8f [2] a8 95 [2] b6 88 [2] b4 89 [2] af 8f [2] b3 88 [2] af a7 }

  condition:
    any of them
}