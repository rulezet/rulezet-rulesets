rule TTP_XOR_QUAD_CurrentVersionRun_1811 {
  strings:
    $key_1811 = { 4b 7e [2] 6f 70 [2] 44 5c [2] 6a 7e [2] 7e 65 [2] 71 7f [2] 6f 62 [2] 6d 63 [2] 76 65 [2] 6a 62 [2] 76 4d }

  condition:
    any of them
}