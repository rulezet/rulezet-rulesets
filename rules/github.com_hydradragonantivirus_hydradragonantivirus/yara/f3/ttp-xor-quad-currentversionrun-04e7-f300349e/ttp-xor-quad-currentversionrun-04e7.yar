rule TTP_XOR_QUAD_CurrentVersionRun_04e7 {
  strings:
    $key_04e7 = { 57 88 [2] 73 86 [2] 58 aa [2] 76 88 [2] 62 93 [2] 6d 89 [2] 73 94 [2] 71 95 [2] 6a 93 [2] 76 94 [2] 6a bb }

  condition:
    any of them
}