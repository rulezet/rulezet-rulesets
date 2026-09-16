rule TTP_XOR_QUAD_CurrentVersionRun_2196 {
  strings:
    $key_2196 = { 72 f9 [2] 56 f7 [2] 7d db [2] 53 f9 [2] 47 e2 [2] 48 f8 [2] 56 e5 [2] 54 e4 [2] 4f e2 [2] 53 e5 [2] 4f ca }

  condition:
    any of them
}