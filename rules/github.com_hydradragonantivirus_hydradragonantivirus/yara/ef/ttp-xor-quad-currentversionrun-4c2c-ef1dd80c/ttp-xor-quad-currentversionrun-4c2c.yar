rule TTP_XOR_QUAD_CurrentVersionRun_4c2c {
  strings:
    $key_4c2c = { 1f 43 [2] 3b 4d [2] 10 61 [2] 3e 43 [2] 2a 58 [2] 25 42 [2] 3b 5f [2] 39 5e [2] 22 58 [2] 3e 5f [2] 22 70 }

  condition:
    any of them
}