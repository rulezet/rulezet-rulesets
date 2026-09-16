rule TTP_XOR_QUAD_CurrentVersionRun_2e93 {
  strings:
    $key_2e93 = { 7d fc [2] 59 f2 [2] 72 de [2] 5c fc [2] 48 e7 [2] 47 fd [2] 59 e0 [2] 5b e1 [2] 40 e7 [2] 5c e0 [2] 40 cf }

  condition:
    any of them
}