rule TTP_XOR_QUAD_CurrentVersionRun_9aee {
  strings:
    $key_9aee = { c9 81 [2] ed 8f [2] c6 a3 [2] e8 81 [2] fc 9a [2] f3 80 [2] ed 9d [2] ef 9c [2] f4 9a [2] e8 9d [2] f4 b2 }

  condition:
    any of them
}