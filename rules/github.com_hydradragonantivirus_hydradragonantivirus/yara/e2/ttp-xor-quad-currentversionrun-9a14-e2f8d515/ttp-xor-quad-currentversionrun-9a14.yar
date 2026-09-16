rule TTP_XOR_QUAD_CurrentVersionRun_9a14 {
  strings:
    $key_9a14 = { c9 7b [2] ed 75 [2] c6 59 [2] e8 7b [2] fc 60 [2] f3 7a [2] ed 67 [2] ef 66 [2] f4 60 [2] e8 67 [2] f4 48 }

  condition:
    any of them
}