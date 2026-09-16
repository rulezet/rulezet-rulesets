rule TTP_XOR_QUAD_CurrentVersionRun_2c4c {
  strings:
    $key_2c4c = { 7f 23 [2] 5b 2d [2] 70 01 [2] 5e 23 [2] 4a 38 [2] 45 22 [2] 5b 3f [2] 59 3e [2] 42 38 [2] 5e 3f [2] 42 10 }

  condition:
    any of them
}