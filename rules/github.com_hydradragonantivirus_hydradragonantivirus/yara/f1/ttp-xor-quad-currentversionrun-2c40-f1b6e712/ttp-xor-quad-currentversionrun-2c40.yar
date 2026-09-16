rule TTP_XOR_QUAD_CurrentVersionRun_2c40 {
  strings:
    $key_2c40 = { 7f 2f [2] 5b 21 [2] 70 0d [2] 5e 2f [2] 4a 34 [2] 45 2e [2] 5b 33 [2] 59 32 [2] 42 34 [2] 5e 33 [2] 42 1c }

  condition:
    any of them
}