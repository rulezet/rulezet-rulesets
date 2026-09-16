rule TTP_XOR_QUAD_CurrentVersionRun_7811 {
  strings:
    $key_7811 = { 2b 7e [2] 0f 70 [2] 24 5c [2] 0a 7e [2] 1e 65 [2] 11 7f [2] 0f 62 [2] 0d 63 [2] 16 65 [2] 0a 62 [2] 16 4d }

  condition:
    any of them
}