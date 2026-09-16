rule TTP_XOR_QUAD_CurrentVersionRun_703d {
  strings:
    $key_703d = { 23 52 [2] 07 5c [2] 2c 70 [2] 02 52 [2] 16 49 [2] 19 53 [2] 07 4e [2] 05 4f [2] 1e 49 [2] 02 4e [2] 1e 61 }

  condition:
    any of them
}