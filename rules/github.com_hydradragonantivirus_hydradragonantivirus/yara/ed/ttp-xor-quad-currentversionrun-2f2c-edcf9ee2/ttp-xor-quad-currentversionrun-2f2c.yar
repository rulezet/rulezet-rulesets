rule TTP_XOR_QUAD_CurrentVersionRun_2f2c {
  strings:
    $key_2f2c = { 7c 43 [2] 58 4d [2] 73 61 [2] 5d 43 [2] 49 58 [2] 46 42 [2] 58 5f [2] 5a 5e [2] 41 58 [2] 5d 5f [2] 41 70 }

  condition:
    any of them
}