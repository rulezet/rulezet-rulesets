rule TTP_XOR_QUAD_CurrentVersionRun_70e7 {
  strings:
    $key_70e7 = { 23 88 [2] 07 86 [2] 2c aa [2] 02 88 [2] 16 93 [2] 19 89 [2] 07 94 [2] 05 95 [2] 1e 93 [2] 02 94 [2] 1e bb }

  condition:
    any of them
}