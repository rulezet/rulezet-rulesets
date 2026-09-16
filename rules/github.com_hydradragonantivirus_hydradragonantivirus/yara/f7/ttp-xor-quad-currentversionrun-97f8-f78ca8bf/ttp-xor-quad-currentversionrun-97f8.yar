rule TTP_XOR_QUAD_CurrentVersionRun_97f8 {
  strings:
    $key_97f8 = { c4 97 [2] e0 99 [2] cb b5 [2] e5 97 [2] f1 8c [2] fe 96 [2] e0 8b [2] e2 8a [2] f9 8c [2] e5 8b [2] f9 a4 }

  condition:
    any of them
}