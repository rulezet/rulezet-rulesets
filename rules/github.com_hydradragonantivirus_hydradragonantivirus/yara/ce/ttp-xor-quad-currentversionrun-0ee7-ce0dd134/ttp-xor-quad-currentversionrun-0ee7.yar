rule TTP_XOR_QUAD_CurrentVersionRun_0ee7 {
  strings:
    $key_0ee7 = { 5d 88 [2] 79 86 [2] 52 aa [2] 7c 88 [2] 68 93 [2] 67 89 [2] 79 94 [2] 7b 95 [2] 60 93 [2] 7c 94 [2] 60 bb }

  condition:
    any of them
}