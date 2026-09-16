rule TTP_XOR_QUAD_CurrentVersionRun_90fa {
  strings:
    $key_90fa = { c3 95 [2] e7 9b [2] cc b7 [2] e2 95 [2] f6 8e [2] f9 94 [2] e7 89 [2] e5 88 [2] fe 8e [2] e2 89 [2] fe a6 }

  condition:
    any of them
}