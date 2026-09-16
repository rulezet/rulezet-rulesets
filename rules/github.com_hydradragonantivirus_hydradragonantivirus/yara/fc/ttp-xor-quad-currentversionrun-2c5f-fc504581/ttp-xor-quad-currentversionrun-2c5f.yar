rule TTP_XOR_QUAD_CurrentVersionRun_2c5f {
  strings:
    $key_2c5f = { 7f 30 [2] 5b 3e [2] 70 12 [2] 5e 30 [2] 4a 2b [2] 45 31 [2] 5b 2c [2] 59 2d [2] 42 2b [2] 5e 2c [2] 42 03 }

  condition:
    any of them
}