rule TTP_XOR_QUAD_CurrentVersionRun_c182 {
  strings:
    $key_c182 = { 92 ed [2] b6 e3 [2] 9d cf [2] b3 ed [2] a7 f6 [2] a8 ec [2] b6 f1 [2] b4 f0 [2] af f6 [2] b3 f1 [2] af de }

  condition:
    any of them
}