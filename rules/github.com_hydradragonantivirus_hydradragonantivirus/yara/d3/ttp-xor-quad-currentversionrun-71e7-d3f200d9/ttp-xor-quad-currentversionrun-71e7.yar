rule TTP_XOR_QUAD_CurrentVersionRun_71e7 {
  strings:
    $key_71e7 = { 22 88 [2] 06 86 [2] 2d aa [2] 03 88 [2] 17 93 [2] 18 89 [2] 06 94 [2] 04 95 [2] 1f 93 [2] 03 94 [2] 1f bb }

  condition:
    any of them
}