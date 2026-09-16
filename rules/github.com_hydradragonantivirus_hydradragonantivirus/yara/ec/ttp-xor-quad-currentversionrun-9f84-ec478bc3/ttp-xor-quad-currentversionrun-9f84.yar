rule TTP_XOR_QUAD_CurrentVersionRun_9f84 {
  strings:
    $key_9f84 = { cc eb [2] e8 e5 [2] c3 c9 [2] ed eb [2] f9 f0 [2] f6 ea [2] e8 f7 [2] ea f6 [2] f1 f0 [2] ed f7 [2] f1 d8 }

  condition:
    any of them
}