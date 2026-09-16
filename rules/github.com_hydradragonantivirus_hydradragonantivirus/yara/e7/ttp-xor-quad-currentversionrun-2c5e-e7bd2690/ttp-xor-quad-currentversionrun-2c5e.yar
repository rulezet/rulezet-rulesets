rule TTP_XOR_QUAD_CurrentVersionRun_2c5e {
  strings:
    $key_2c5e = { 7f 31 [2] 5b 3f [2] 70 13 [2] 5e 31 [2] 4a 2a [2] 45 30 [2] 5b 2d [2] 59 2c [2] 42 2a [2] 5e 2d [2] 42 02 }

  condition:
    any of them
}