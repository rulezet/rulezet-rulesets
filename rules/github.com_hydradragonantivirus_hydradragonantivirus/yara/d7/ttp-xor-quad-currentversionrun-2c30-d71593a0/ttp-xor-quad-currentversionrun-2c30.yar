rule TTP_XOR_QUAD_CurrentVersionRun_2c30 {
  strings:
    $key_2c30 = { 7f 5f [2] 5b 51 [2] 70 7d [2] 5e 5f [2] 4a 44 [2] 45 5e [2] 5b 43 [2] 59 42 [2] 42 44 [2] 5e 43 [2] 42 6c }

  condition:
    any of them
}