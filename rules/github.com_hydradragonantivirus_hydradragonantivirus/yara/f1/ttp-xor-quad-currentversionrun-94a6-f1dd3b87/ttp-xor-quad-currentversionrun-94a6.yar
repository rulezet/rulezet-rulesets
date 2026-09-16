rule TTP_XOR_QUAD_CurrentVersionRun_94a6 {
  strings:
    $key_94a6 = { c7 c9 [2] e3 c7 [2] c8 eb [2] e6 c9 [2] f2 d2 [2] fd c8 [2] e3 d5 [2] e1 d4 [2] fa d2 [2] e6 d5 [2] fa fa }

  condition:
    any of them
}