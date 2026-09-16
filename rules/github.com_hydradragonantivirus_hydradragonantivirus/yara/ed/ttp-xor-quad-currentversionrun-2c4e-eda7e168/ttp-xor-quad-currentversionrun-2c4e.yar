rule TTP_XOR_QUAD_CurrentVersionRun_2c4e {
  strings:
    $key_2c4e = { 7f 21 [2] 5b 2f [2] 70 03 [2] 5e 21 [2] 4a 3a [2] 45 20 [2] 5b 3d [2] 59 3c [2] 42 3a [2] 5e 3d [2] 42 12 }

  condition:
    any of them
}