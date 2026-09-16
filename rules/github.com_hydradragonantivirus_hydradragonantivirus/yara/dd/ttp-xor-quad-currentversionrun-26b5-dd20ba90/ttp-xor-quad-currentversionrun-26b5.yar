rule TTP_XOR_QUAD_CurrentVersionRun_26b5 {
  strings:
    $key_26b5 = { 75 da [2] 51 d4 [2] 7a f8 [2] 54 da [2] 40 c1 [2] 4f db [2] 51 c6 [2] 53 c7 [2] 48 c1 [2] 54 c6 [2] 48 e9 }

  condition:
    any of them
}