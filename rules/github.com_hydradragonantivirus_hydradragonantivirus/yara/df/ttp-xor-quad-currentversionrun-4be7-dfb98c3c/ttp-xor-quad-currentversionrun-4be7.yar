rule TTP_XOR_QUAD_CurrentVersionRun_4be7 {
  strings:
    $key_4be7 = { 18 88 [2] 3c 86 [2] 17 aa [2] 39 88 [2] 2d 93 [2] 22 89 [2] 3c 94 [2] 3e 95 [2] 25 93 [2] 39 94 [2] 25 bb }

  condition:
    any of them
}