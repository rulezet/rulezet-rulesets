rule TTP_XOR_QUAD_CurrentVersionRun_c582 {
  strings:
    $key_c582 = { 96 ed [2] b2 e3 [2] 99 cf [2] b7 ed [2] a3 f6 [2] ac ec [2] b2 f1 [2] b0 f0 [2] ab f6 [2] b7 f1 [2] ab de }

  condition:
    any of them
}