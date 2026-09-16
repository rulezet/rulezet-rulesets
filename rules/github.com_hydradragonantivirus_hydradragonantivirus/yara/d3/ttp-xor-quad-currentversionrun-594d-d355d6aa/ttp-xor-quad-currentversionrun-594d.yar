rule TTP_XOR_QUAD_CurrentVersionRun_594d {
  strings:
    $key_594d = { 0a 22 [2] 2e 2c [2] 05 00 [2] 2b 22 [2] 3f 39 [2] 30 23 [2] 2e 3e [2] 2c 3f [2] 37 39 [2] 2b 3e [2] 37 11 }

  condition:
    any of them
}