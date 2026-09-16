rule TTP_XOR_QUAD_CurrentVersionRun_9d85 {
  strings:
    $key_9d85 = { ce ea [2] ea e4 [2] c1 c8 [2] ef ea [2] fb f1 [2] f4 eb [2] ea f6 [2] e8 f7 [2] f3 f1 [2] ef f6 [2] f3 d9 }

  condition:
    any of them
}