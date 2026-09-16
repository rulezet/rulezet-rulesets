rule TTP_XOR_QUAD_CurrentVersionRun_2c7d {
  strings:
    $key_2c7d = { 7f 12 [2] 5b 1c [2] 70 30 [2] 5e 12 [2] 4a 09 [2] 45 13 [2] 5b 0e [2] 59 0f [2] 42 09 [2] 5e 0e [2] 42 21 }

  condition:
    any of them
}