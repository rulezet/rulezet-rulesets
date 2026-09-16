rule TTP_XOR_QUAD_CurrentVersionRun_2396 {
  strings:
    $key_2396 = { 70 f9 [2] 54 f7 [2] 7f db [2] 51 f9 [2] 45 e2 [2] 4a f8 [2] 54 e5 [2] 56 e4 [2] 4d e2 [2] 51 e5 [2] 4d ca }

  condition:
    any of them
}