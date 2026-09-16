rule TTP_XOR_QUAD_CurrentVersionRun_8b4e {
  strings:
    $key_8b4e = { d8 21 [2] fc 2f [2] d7 03 [2] f9 21 [2] ed 3a [2] e2 20 [2] fc 3d [2] fe 3c [2] e5 3a [2] f9 3d [2] e5 12 }

  condition:
    any of them
}