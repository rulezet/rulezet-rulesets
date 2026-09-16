rule TTP_XOR_QUAD_CurrentVersionRun_fae7 {
  strings:
    $key_fae7 = { a9 88 [2] 8d 86 [2] a6 aa [2] 88 88 [2] 9c 93 [2] 93 89 [2] 8d 94 [2] 8f 95 [2] 94 93 [2] 88 94 [2] 94 bb }

  condition:
    any of them
}