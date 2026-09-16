rule TTP_XOR_QUAD_CurrentVersionRun_c693 {
  strings:
    $key_c693 = { 95 fc [2] b1 f2 [2] 9a de [2] b4 fc [2] a0 e7 [2] af fd [2] b1 e0 [2] b3 e1 [2] a8 e7 [2] b4 e0 [2] a8 cf }

  condition:
    any of them
}