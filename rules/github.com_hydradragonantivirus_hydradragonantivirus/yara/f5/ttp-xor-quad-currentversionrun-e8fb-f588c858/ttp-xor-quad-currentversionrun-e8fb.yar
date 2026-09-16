rule TTP_XOR_QUAD_CurrentVersionRun_e8fb {
  strings:
    $key_e8fb = { bb 94 [2] 9f 9a [2] b4 b6 [2] 9a 94 [2] 8e 8f [2] 81 95 [2] 9f 88 [2] 9d 89 [2] 86 8f [2] 9a 88 [2] 86 a7 }

  condition:
    any of them
}