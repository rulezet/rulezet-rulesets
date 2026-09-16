rule TTP_XOR_QUAD_CurrentVersionRun_95e9 {
  strings:
    $key_95e9 = { c6 86 [2] e2 88 [2] c9 a4 [2] e7 86 [2] f3 9d [2] fc 87 [2] e2 9a [2] e0 9b [2] fb 9d [2] e7 9a [2] fb b5 }

  condition:
    any of them
}