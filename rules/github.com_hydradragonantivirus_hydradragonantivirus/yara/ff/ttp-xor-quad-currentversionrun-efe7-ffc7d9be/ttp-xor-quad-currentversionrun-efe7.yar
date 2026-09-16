rule TTP_XOR_QUAD_CurrentVersionRun_efe7 {
  strings:
    $key_efe7 = { bc 88 [2] 98 86 [2] b3 aa [2] 9d 88 [2] 89 93 [2] 86 89 [2] 98 94 [2] 9a 95 [2] 81 93 [2] 9d 94 [2] 81 bb }

  condition:
    any of them
}