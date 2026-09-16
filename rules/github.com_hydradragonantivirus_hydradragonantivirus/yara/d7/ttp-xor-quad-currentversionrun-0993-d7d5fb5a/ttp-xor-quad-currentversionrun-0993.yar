rule TTP_XOR_QUAD_CurrentVersionRun_0993 {
  strings:
    $key_0993 = { 5a fc [2] 7e f2 [2] 55 de [2] 7b fc [2] 6f e7 [2] 60 fd [2] 7e e0 [2] 7c e1 [2] 67 e7 [2] 7b e0 [2] 67 cf }

  condition:
    any of them
}