rule TTP_XOR_QUAD_CurrentVersionRun_5811 {
  strings:
    $key_5811 = { 0b 7e [2] 2f 70 [2] 04 5c [2] 2a 7e [2] 3e 65 [2] 31 7f [2] 2f 62 [2] 2d 63 [2] 36 65 [2] 2a 62 [2] 36 4d }

  condition:
    any of them
}