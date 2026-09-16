rule TTP_XOR_QUAD_CurrentVersionRun_93e7 {
  strings:
    $key_93e7 = { c0 88 [2] e4 86 [2] cf aa [2] e1 88 [2] f5 93 [2] fa 89 [2] e4 94 [2] e6 95 [2] fd 93 [2] e1 94 [2] fd bb }

  condition:
    any of them
}