rule TTP_XOR_QUAD_CurrentVersionRun_9fbe {
  strings:
    $key_9fbe = { cc d1 [2] e8 df [2] c3 f3 [2] ed d1 [2] f9 ca [2] f6 d0 [2] e8 cd [2] ea cc [2] f1 ca [2] ed cd [2] f1 e2 }

  condition:
    any of them
}