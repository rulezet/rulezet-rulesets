rule TTP_XOR_QUAD_CurrentVersionRun_c682 {
  strings:
    $key_c682 = { 95 ed [2] b1 e3 [2] 9a cf [2] b4 ed [2] a0 f6 [2] af ec [2] b1 f1 [2] b3 f0 [2] a8 f6 [2] b4 f1 [2] a8 de }

  condition:
    any of them
}