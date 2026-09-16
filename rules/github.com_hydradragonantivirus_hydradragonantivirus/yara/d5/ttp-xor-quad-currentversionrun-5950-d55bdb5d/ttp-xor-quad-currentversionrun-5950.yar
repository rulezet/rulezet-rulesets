rule TTP_XOR_QUAD_CurrentVersionRun_5950 {
  strings:
    $key_5950 = { 0a 3f [2] 2e 31 [2] 05 1d [2] 2b 3f [2] 3f 24 [2] 30 3e [2] 2e 23 [2] 2c 22 [2] 37 24 [2] 2b 23 [2] 37 0c }

  condition:
    any of them
}