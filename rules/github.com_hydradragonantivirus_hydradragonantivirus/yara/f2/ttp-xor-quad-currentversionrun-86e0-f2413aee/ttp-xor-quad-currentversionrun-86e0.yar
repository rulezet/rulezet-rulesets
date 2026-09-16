rule TTP_XOR_QUAD_CurrentVersionRun_86e0 {
  strings:
    $key_86e0 = { d5 8f [2] f1 81 [2] da ad [2] f4 8f [2] e0 94 [2] ef 8e [2] f1 93 [2] f3 92 [2] e8 94 [2] f4 93 [2] e8 bc }

  condition:
    any of them
}