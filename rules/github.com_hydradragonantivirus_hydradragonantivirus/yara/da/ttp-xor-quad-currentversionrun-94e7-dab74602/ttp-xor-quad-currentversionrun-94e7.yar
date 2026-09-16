rule TTP_XOR_QUAD_CurrentVersionRun_94e7 {
  strings:
    $key_94e7 = { c7 88 [2] e3 86 [2] c8 aa [2] e6 88 [2] f2 93 [2] fd 89 [2] e3 94 [2] e1 95 [2] fa 93 [2] e6 94 [2] fa bb }

  condition:
    any of them
}