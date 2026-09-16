rule TTP_XOR_QUAD_CurrentVersionRun_9d9a {
  strings:
    $key_9d9a = { ce f5 [2] ea fb [2] c1 d7 [2] ef f5 [2] fb ee [2] f4 f4 [2] ea e9 [2] e8 e8 [2] f3 ee [2] ef e9 [2] f3 c6 }

  condition:
    any of them
}