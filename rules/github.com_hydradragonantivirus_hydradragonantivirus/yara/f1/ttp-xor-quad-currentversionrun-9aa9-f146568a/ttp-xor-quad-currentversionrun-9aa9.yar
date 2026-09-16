rule TTP_XOR_QUAD_CurrentVersionRun_9aa9 {
  strings:
    $key_9aa9 = { c9 c6 [2] ed c8 [2] c6 e4 [2] e8 c6 [2] fc dd [2] f3 c7 [2] ed da [2] ef db [2] f4 dd [2] e8 da [2] f4 f5 }

  condition:
    any of them
}