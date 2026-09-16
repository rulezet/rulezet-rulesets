rule TTP_XOR_QUAD_CurrentVersionRun_5be7 {
  strings:
    $key_5be7 = { 08 88 [2] 2c 86 [2] 07 aa [2] 29 88 [2] 3d 93 [2] 32 89 [2] 2c 94 [2] 2e 95 [2] 35 93 [2] 29 94 [2] 35 bb }

  condition:
    any of them
}