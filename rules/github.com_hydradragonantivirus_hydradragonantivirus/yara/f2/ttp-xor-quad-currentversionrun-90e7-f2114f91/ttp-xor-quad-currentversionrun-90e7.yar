rule TTP_XOR_QUAD_CurrentVersionRun_90e7 {
  strings:
    $key_90e7 = { c3 88 [2] e7 86 [2] cc aa [2] e2 88 [2] f6 93 [2] f9 89 [2] e7 94 [2] e5 95 [2] fe 93 [2] e2 94 [2] fe bb }

  condition:
    any of them
}