rule TTP_XOR_QUAD_CurrentVersionRun_29e7 {
  strings:
    $key_29e7 = { 7a 88 [2] 5e 86 [2] 75 aa [2] 5b 88 [2] 4f 93 [2] 40 89 [2] 5e 94 [2] 5c 95 [2] 47 93 [2] 5b 94 [2] 47 bb }

  condition:
    any of them
}