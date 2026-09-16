rule TTP_XOR_QUAD_CurrentVersionRun_bbe7 {
  strings:
    $key_bbe7 = { e8 88 [2] cc 86 [2] e7 aa [2] c9 88 [2] dd 93 [2] d2 89 [2] cc 94 [2] ce 95 [2] d5 93 [2] c9 94 [2] d5 bb }

  condition:
    any of them
}