rule TTP_XOR_QUAD_CurrentVersionRun_2c51 {
  strings:
    $key_2c51 = { 7f 3e [2] 5b 30 [2] 70 1c [2] 5e 3e [2] 4a 25 [2] 45 3f [2] 5b 22 [2] 59 23 [2] 42 25 [2] 5e 22 [2] 42 0d }

  condition:
    any of them
}