rule TTP_XOR_QUAD_CurrentVersionRun_448a {
  strings:
    $key_448a = { 17 e5 [2] 33 eb [2] 18 c7 [2] 36 e5 [2] 22 fe [2] 2d e4 [2] 33 f9 [2] 31 f8 [2] 2a fe [2] 36 f9 [2] 2a d6 }

  condition:
    any of them
}