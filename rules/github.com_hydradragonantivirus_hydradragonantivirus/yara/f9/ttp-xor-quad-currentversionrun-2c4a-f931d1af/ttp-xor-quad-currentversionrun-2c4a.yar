rule TTP_XOR_QUAD_CurrentVersionRun_2c4a {
  strings:
    $key_2c4a = { 7f 25 [2] 5b 2b [2] 70 07 [2] 5e 25 [2] 4a 3e [2] 45 24 [2] 5b 39 [2] 59 38 [2] 42 3e [2] 5e 39 [2] 42 16 }

  condition:
    any of them
}