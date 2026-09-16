rule TTP_XOR_QUAD_CurrentVersionRun_9466 {
  strings:
    $key_9466 = { c7 09 [2] e3 07 [2] c8 2b [2] e6 09 [2] f2 12 [2] fd 08 [2] e3 15 [2] e1 14 [2] fa 12 [2] e6 15 [2] fa 3a }

  condition:
    any of them
}