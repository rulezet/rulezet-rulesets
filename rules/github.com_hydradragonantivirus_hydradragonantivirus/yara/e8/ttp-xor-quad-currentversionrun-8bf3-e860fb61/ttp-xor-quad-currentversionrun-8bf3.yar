rule TTP_XOR_QUAD_CurrentVersionRun_8bf3 {
  strings:
    $key_8bf3 = { d8 9c [2] fc 92 [2] d7 be [2] f9 9c [2] ed 87 [2] e2 9d [2] fc 80 [2] fe 81 [2] e5 87 [2] f9 80 [2] e5 af }

  condition:
    any of them
}