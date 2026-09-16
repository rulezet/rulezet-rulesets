rule TTP_XOR_QUAD_CurrentVersionRun_5e3a {
  strings:
    $key_5e3a = { 0d 55 [2] 29 5b [2] 02 77 [2] 2c 55 [2] 38 4e [2] 37 54 [2] 29 49 [2] 2b 48 [2] 30 4e [2] 2c 49 [2] 30 66 }

  condition:
    any of them
}