rule TTP_XOR_QUAD_CurrentVersionRun_e793 {
  strings:
    $key_e793 = { b4 fc [2] 90 f2 [2] bb de [2] 95 fc [2] 81 e7 [2] 8e fd [2] 90 e0 [2] 92 e1 [2] 89 e7 [2] 95 e0 [2] 89 cf }

  condition:
    any of them
}