rule TTP_XOR_QUAD_CurrentVersionRun_54e7 {
  strings:
    $key_54e7 = { 07 88 [2] 23 86 [2] 08 aa [2] 26 88 [2] 32 93 [2] 3d 89 [2] 23 94 [2] 21 95 [2] 3a 93 [2] 26 94 [2] 3a bb }

  condition:
    any of them
}