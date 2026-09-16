rule TTP_XOR_QUAD_CurrentVersionRun_847e {
  strings:
    $key_847e = { d7 11 [2] f3 1f [2] d8 33 [2] f6 11 [2] e2 0a [2] ed 10 [2] f3 0d [2] f1 0c [2] ea 0a [2] f6 0d [2] ea 22 }

  condition:
    any of them
}