rule TTP_XOR_QUAD_CurrentVersionRun_97e2 {
  strings:
    $key_97e2 = { c4 8d [2] e0 83 [2] cb af [2] e5 8d [2] f1 96 [2] fe 8c [2] e0 91 [2] e2 90 [2] f9 96 [2] e5 91 [2] f9 be }

  condition:
    any of them
}