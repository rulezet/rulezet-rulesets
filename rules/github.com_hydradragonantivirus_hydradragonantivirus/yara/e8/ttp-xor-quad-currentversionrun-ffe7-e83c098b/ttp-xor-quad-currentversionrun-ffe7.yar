rule TTP_XOR_QUAD_CurrentVersionRun_ffe7 {
  strings:
    $key_ffe7 = { ac 88 [2] 88 86 [2] a3 aa [2] 8d 88 [2] 99 93 [2] 96 89 [2] 88 94 [2] 8a 95 [2] 91 93 [2] 8d 94 [2] 91 bb }

  condition:
    any of them
}