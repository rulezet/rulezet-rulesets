rule TTP_XOR_QUAD_CurrentVersionRun_5d93 {
  strings:
    $key_5d93 = { 0e fc [2] 2a f2 [2] 01 de [2] 2f fc [2] 3b e7 [2] 34 fd [2] 2a e0 [2] 28 e1 [2] 33 e7 [2] 2f e0 [2] 33 cf }

  condition:
    any of them
}