rule TTP_XOR_QUAD_CurrentVersionRun_51e7 {
  strings:
    $key_51e7 = { 02 88 [2] 26 86 [2] 0d aa [2] 23 88 [2] 37 93 [2] 38 89 [2] 26 94 [2] 24 95 [2] 3f 93 [2] 23 94 [2] 3f bb }

  condition:
    any of them
}