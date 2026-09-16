rule TTP_XOR_QUAD_CurrentVersionRun_707d {
  strings:
    $key_707d = { 23 12 [2] 07 1c [2] 2c 30 [2] 02 12 [2] 16 09 [2] 19 13 [2] 07 0e [2] 05 0f [2] 1e 09 [2] 02 0e [2] 1e 21 }

  condition:
    any of them
}