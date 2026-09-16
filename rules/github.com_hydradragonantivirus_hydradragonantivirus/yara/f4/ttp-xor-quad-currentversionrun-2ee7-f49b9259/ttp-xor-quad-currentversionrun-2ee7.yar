rule TTP_XOR_QUAD_CurrentVersionRun_2ee7 {
  strings:
    $key_2ee7 = { 7d 88 [2] 59 86 [2] 72 aa [2] 5c 88 [2] 48 93 [2] 47 89 [2] 59 94 [2] 5b 95 [2] 40 93 [2] 5c 94 [2] 40 bb }

  condition:
    any of them
}