rule TTP_XOR_QUAD_CurrentVersionRun_2c62 {
  strings:
    $key_2c62 = { 7f 0d [2] 5b 03 [2] 70 2f [2] 5e 0d [2] 4a 16 [2] 45 0c [2] 5b 11 [2] 59 10 [2] 42 16 [2] 5e 11 [2] 42 3e }

  condition:
    any of them
}