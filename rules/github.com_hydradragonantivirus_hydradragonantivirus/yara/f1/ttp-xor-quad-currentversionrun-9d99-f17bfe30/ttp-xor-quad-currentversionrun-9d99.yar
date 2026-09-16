rule TTP_XOR_QUAD_CurrentVersionRun_9d99 {
  strings:
    $key_9d99 = { ce f6 [2] ea f8 [2] c1 d4 [2] ef f6 [2] fb ed [2] f4 f7 [2] ea ea [2] e8 eb [2] f3 ed [2] ef ea [2] f3 c5 }

  condition:
    any of them
}