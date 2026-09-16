rule TTP_XOR_QUAD_CurrentVersionRun_d182 {
  strings:
    $key_d182 = { 82 ed [2] a6 e3 [2] 8d cf [2] a3 ed [2] b7 f6 [2] b8 ec [2] a6 f1 [2] a4 f0 [2] bf f6 [2] a3 f1 [2] bf de }

  condition:
    any of them
}