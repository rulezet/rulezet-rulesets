rule TTP_XOR_QUAD_CurrentVersionRun_3ce7 {
  strings:
    $key_3ce7 = { 6f 88 [2] 4b 86 [2] 60 aa [2] 4e 88 [2] 5a 93 [2] 55 89 [2] 4b 94 [2] 49 95 [2] 52 93 [2] 4e 94 [2] 52 bb }

  condition:
    any of them
}