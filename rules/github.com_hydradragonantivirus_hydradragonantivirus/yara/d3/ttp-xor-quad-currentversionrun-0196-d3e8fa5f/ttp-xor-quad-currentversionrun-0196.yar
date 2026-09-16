rule TTP_XOR_QUAD_CurrentVersionRun_0196 {
  strings:
    $key_0196 = { 52 f9 [2] 76 f7 [2] 5d db [2] 73 f9 [2] 67 e2 [2] 68 f8 [2] 76 e5 [2] 74 e4 [2] 6f e2 [2] 73 e5 [2] 6f ca }

  condition:
    any of them
}