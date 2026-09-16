rule TTP_XOR_QUAD_CurrentVersionRun_1ae7 {
  strings:
    $key_1ae7 = { 49 88 [2] 6d 86 [2] 46 aa [2] 68 88 [2] 7c 93 [2] 73 89 [2] 6d 94 [2] 6f 95 [2] 74 93 [2] 68 94 [2] 74 bb }

  condition:
    any of them
}