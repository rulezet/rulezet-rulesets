rule TTP_XOR_QUAD_CurrentVersionRun_81e7 {
  strings:
    $key_81e7 = { d2 88 [2] f6 86 [2] dd aa [2] f3 88 [2] e7 93 [2] e8 89 [2] f6 94 [2] f4 95 [2] ef 93 [2] f3 94 [2] ef bb }

  condition:
    any of them
}