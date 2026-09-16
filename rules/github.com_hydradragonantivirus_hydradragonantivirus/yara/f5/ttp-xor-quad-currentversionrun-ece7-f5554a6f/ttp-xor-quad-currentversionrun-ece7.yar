rule TTP_XOR_QUAD_CurrentVersionRun_ece7 {
  strings:
    $key_ece7 = { bf 88 [2] 9b 86 [2] b0 aa [2] 9e 88 [2] 8a 93 [2] 85 89 [2] 9b 94 [2] 99 95 [2] 82 93 [2] 9e 94 [2] 82 bb }

  condition:
    any of them
}