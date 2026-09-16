rule TTP_XOR_QUAD_CurrentVersionRun_707a {
  strings:
    $key_707a = { 23 15 [2] 07 1b [2] 2c 37 [2] 02 15 [2] 16 0e [2] 19 14 [2] 07 09 [2] 05 08 [2] 1e 0e [2] 02 09 [2] 1e 26 }

  condition:
    any of them
}