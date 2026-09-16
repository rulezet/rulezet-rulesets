rule TTP_XOR_QUAD_CurrentVersionRun_7911 {
  strings:
    $key_7911 = { 2a 7e [2] 0e 70 [2] 25 5c [2] 0b 7e [2] 1f 65 [2] 10 7f [2] 0e 62 [2] 0c 63 [2] 17 65 [2] 0b 62 [2] 17 4d }

  condition:
    any of them
}