rule TTP_XOR_QUAD_CurrentVersionRun_d693 {
  strings:
    $key_d693 = { 85 fc [2] a1 f2 [2] 8a de [2] a4 fc [2] b0 e7 [2] bf fd [2] a1 e0 [2] a3 e1 [2] b8 e7 [2] a4 e0 [2] b8 cf }

  condition:
    any of them
}