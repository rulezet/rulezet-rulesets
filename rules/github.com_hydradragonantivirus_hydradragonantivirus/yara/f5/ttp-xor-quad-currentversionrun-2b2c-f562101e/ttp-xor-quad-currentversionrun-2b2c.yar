rule TTP_XOR_QUAD_CurrentVersionRun_2b2c {
  strings:
    $key_2b2c = { 78 43 [2] 5c 4d [2] 77 61 [2] 59 43 [2] 4d 58 [2] 42 42 [2] 5c 5f [2] 5e 5e [2] 45 58 [2] 59 5f [2] 45 70 }

  condition:
    any of them
}