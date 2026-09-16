rule TTP_XOR_QUAD_CurrentVersionRun_8b53 {
  strings:
    $key_8b53 = { d8 3c [2] fc 32 [2] d7 1e [2] f9 3c [2] ed 27 [2] e2 3d [2] fc 20 [2] fe 21 [2] e5 27 [2] f9 20 [2] e5 0f }

  condition:
    any of them
}