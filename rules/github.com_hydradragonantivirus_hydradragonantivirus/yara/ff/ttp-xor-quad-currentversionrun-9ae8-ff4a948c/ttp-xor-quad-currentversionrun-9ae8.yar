rule TTP_XOR_QUAD_CurrentVersionRun_9ae8 {
  strings:
    $key_9ae8 = { c9 87 [2] ed 89 [2] c6 a5 [2] e8 87 [2] fc 9c [2] f3 86 [2] ed 9b [2] ef 9a [2] f4 9c [2] e8 9b [2] f4 b4 }

  condition:
    any of them
}