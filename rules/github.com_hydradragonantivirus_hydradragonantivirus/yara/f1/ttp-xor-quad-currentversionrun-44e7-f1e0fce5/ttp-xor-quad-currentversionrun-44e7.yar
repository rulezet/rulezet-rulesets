rule TTP_XOR_QUAD_CurrentVersionRun_44e7 {
  strings:
    $key_44e7 = { 17 88 [2] 33 86 [2] 18 aa [2] 36 88 [2] 22 93 [2] 2d 89 [2] 33 94 [2] 31 95 [2] 2a 93 [2] 36 94 [2] 2a bb }

  condition:
    any of them
}