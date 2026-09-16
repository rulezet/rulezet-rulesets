rule TTP_XOR_QUAD_CurrentVersionRun_674d {
  strings:
    $key_674d = { 34 22 [2] 10 2c [2] 3b 00 [2] 15 22 [2] 01 39 [2] 0e 23 [2] 10 3e [2] 12 3f [2] 09 39 [2] 15 3e [2] 09 11 }

  condition:
    any of them
}