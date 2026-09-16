rule TTP_XOR_QUAD_CurrentVersionRun_7050 {
  strings:
    $key_7050 = { 23 3f [2] 07 31 [2] 2c 1d [2] 02 3f [2] 16 24 [2] 19 3e [2] 07 23 [2] 05 22 [2] 1e 24 [2] 02 23 [2] 1e 0c }

  condition:
    any of them
}