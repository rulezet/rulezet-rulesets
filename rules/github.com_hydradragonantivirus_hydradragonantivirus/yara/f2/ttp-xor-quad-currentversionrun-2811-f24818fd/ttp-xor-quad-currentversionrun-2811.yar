rule TTP_XOR_QUAD_CurrentVersionRun_2811 {
  strings:
    $key_2811 = { 7b 7e [2] 5f 70 [2] 74 5c [2] 5a 7e [2] 4e 65 [2] 41 7f [2] 5f 62 [2] 5d 63 [2] 46 65 [2] 5a 62 [2] 46 4d }

  condition:
    any of them
}