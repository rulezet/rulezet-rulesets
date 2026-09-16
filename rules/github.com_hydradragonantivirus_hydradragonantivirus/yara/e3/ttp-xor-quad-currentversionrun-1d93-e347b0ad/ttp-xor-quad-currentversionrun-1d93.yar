rule TTP_XOR_QUAD_CurrentVersionRun_1d93 {
  strings:
    $key_1d93 = { 4e fc [2] 6a f2 [2] 41 de [2] 6f fc [2] 7b e7 [2] 74 fd [2] 6a e0 [2] 68 e1 [2] 73 e7 [2] 6f e0 [2] 73 cf }

  condition:
    any of them
}