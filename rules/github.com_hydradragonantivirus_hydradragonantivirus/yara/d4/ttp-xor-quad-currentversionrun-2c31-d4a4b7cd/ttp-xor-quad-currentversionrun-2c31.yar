rule TTP_XOR_QUAD_CurrentVersionRun_2c31 {
  strings:
    $key_2c31 = { 7f 5e [2] 5b 50 [2] 70 7c [2] 5e 5e [2] 4a 45 [2] 45 5f [2] 5b 42 [2] 59 43 [2] 42 45 [2] 5e 42 [2] 42 6d }

  condition:
    any of them
}