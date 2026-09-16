rule TTP_XOR_QUAD_CurrentVersionRun_4ce7 {
  strings:
    $key_4ce7 = { 1f 88 [2] 3b 86 [2] 10 aa [2] 3e 88 [2] 2a 93 [2] 25 89 [2] 3b 94 [2] 39 95 [2] 22 93 [2] 3e 94 [2] 22 bb }

  condition:
    any of them
}