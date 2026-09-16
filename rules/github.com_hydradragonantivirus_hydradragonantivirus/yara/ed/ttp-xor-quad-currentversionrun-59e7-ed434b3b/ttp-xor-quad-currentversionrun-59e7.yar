rule TTP_XOR_QUAD_CurrentVersionRun_59e7 {
  strings:
    $key_59e7 = { 0a 88 [2] 2e 86 [2] 05 aa [2] 2b 88 [2] 3f 93 [2] 30 89 [2] 2e 94 [2] 2c 95 [2] 37 93 [2] 2b 94 [2] 37 bb }

  condition:
    any of them
}