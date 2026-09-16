rule TTP_XOR_QUAD_CurrentVersionRun_6911 {
  strings:
    $key_6911 = { 3a 7e [2] 1e 70 [2] 35 5c [2] 1b 7e [2] 0f 65 [2] 00 7f [2] 1e 62 [2] 1c 63 [2] 07 65 [2] 1b 62 [2] 07 4d }

  condition:
    any of them
}