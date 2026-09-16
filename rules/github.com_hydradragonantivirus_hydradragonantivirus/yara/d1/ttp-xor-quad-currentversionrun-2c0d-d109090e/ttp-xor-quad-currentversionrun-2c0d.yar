rule TTP_XOR_QUAD_CurrentVersionRun_2c0d {
  strings:
    $key_2c0d = { 7f 62 [2] 5b 6c [2] 70 40 [2] 5e 62 [2] 4a 79 [2] 45 63 [2] 5b 7e [2] 59 7f [2] 42 79 [2] 5e 7e [2] 42 51 }

  condition:
    any of them
}