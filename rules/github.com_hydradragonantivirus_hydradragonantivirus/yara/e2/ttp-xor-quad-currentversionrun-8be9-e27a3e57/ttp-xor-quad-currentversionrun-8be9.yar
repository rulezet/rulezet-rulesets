rule TTP_XOR_QUAD_CurrentVersionRun_8be9 {
  strings:
    $key_8be9 = { d8 86 [2] fc 88 [2] d7 a4 [2] f9 86 [2] ed 9d [2] e2 87 [2] fc 9a [2] fe 9b [2] e5 9d [2] f9 9a [2] e5 b5 }

  condition:
    any of them
}