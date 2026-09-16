rule TTP_XOR_QUAD_CurrentVersionRun_3c2c {
  strings:
    $key_3c2c = { 6f 43 [2] 4b 4d [2] 60 61 [2] 4e 43 [2] 5a 58 [2] 55 42 [2] 4b 5f [2] 49 5e [2] 52 58 [2] 4e 5f [2] 52 70 }

  condition:
    any of them
}