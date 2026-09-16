rule TTP_XOR_QUAD_CurrentVersionRun_83cf {
  strings:
    $key_83cf = { d0 a0 [2] f4 ae [2] df 82 [2] f1 a0 [2] e5 bb [2] ea a1 [2] f4 bc [2] f6 bd [2] ed bb [2] f1 bc [2] ed 93 }

  condition:
    any of them
}