rule TTP_XOR_QUAD_CurrentVersionRun_e9fb {
  strings:
    $key_e9fb = { ba 94 [2] 9e 9a [2] b5 b6 [2] 9b 94 [2] 8f 8f [2] 80 95 [2] 9e 88 [2] 9c 89 [2] 87 8f [2] 9b 88 [2] 87 a7 }

  condition:
    any of them
}