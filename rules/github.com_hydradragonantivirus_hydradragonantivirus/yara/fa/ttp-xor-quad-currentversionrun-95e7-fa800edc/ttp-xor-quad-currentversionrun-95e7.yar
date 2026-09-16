rule TTP_XOR_QUAD_CurrentVersionRun_95e7 {
  strings:
    $key_95e7 = { c6 88 [2] e2 86 [2] c9 aa [2] e7 88 [2] f3 93 [2] fc 89 [2] e2 94 [2] e0 95 [2] fb 93 [2] e7 94 [2] fb bb }

  condition:
    any of them
}