rule TTP_XOR_QUAD_CurrentVersionRun_6ee7 {
  strings:
    $key_6ee7 = { 3d 88 [2] 19 86 [2] 32 aa [2] 1c 88 [2] 08 93 [2] 07 89 [2] 19 94 [2] 1b 95 [2] 00 93 [2] 1c 94 [2] 00 bb }

  condition:
    any of them
}