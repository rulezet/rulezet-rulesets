rule TTP_XOR_QUAD_CurrentVersionRun_8b0c {
  strings:
    $key_8b0c = { d8 63 [2] fc 6d [2] d7 41 [2] f9 63 [2] ed 78 [2] e2 62 [2] fc 7f [2] fe 7e [2] e5 78 [2] f9 7f [2] e5 50 }

  condition:
    any of them
}