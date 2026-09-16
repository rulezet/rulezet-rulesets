rule TTP_XOR_QUAD_CurrentVersionRun_2c5c {
  strings:
    $key_2c5c = { 7f 33 [2] 5b 3d [2] 70 11 [2] 5e 33 [2] 4a 28 [2] 45 32 [2] 5b 2f [2] 59 2e [2] 42 28 [2] 5e 2f [2] 42 00 }

  condition:
    any of them
}