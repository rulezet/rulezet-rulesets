rule TTP_XOR_QUAD_CurrentVersionRun_8b1e {
  strings:
    $key_8b1e = { d8 71 [2] fc 7f [2] d7 53 [2] f9 71 [2] ed 6a [2] e2 70 [2] fc 6d [2] fe 6c [2] e5 6a [2] f9 6d [2] e5 42 }

  condition:
    any of them
}