rule TTP_XOR_QUAD_CurrentVersionRun_2c03 {
  strings:
    $key_2c03 = { 7f 6c [2] 5b 62 [2] 70 4e [2] 5e 6c [2] 4a 77 [2] 45 6d [2] 5b 70 [2] 59 71 [2] 42 77 [2] 5e 70 [2] 42 5f }

  condition:
    any of them
}