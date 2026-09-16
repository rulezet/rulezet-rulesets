rule TTP_XOR_QUAD_CurrentVersionRun_8bee {
  strings:
    $key_8bee = { d8 81 [2] fc 8f [2] d7 a3 [2] f9 81 [2] ed 9a [2] e2 80 [2] fc 9d [2] fe 9c [2] e5 9a [2] f9 9d [2] e5 b2 }

  condition:
    any of them
}