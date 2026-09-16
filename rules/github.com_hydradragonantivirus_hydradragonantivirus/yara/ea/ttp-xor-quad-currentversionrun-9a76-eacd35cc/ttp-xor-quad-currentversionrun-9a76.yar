rule TTP_XOR_QUAD_CurrentVersionRun_9a76 {
  strings:
    $key_9a76 = { c9 19 [2] ed 17 [2] c6 3b [2] e8 19 [2] fc 02 [2] f3 18 [2] ed 05 [2] ef 04 [2] f4 02 [2] e8 05 [2] f4 2a }

  condition:
    any of them
}