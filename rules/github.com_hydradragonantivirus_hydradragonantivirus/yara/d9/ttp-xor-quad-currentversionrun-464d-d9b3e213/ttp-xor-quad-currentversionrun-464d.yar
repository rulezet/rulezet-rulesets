rule TTP_XOR_QUAD_CurrentVersionRun_464d {
  strings:
    $key_464d = { 15 22 [2] 31 2c [2] 1a 00 [2] 34 22 [2] 20 39 [2] 2f 23 [2] 31 3e [2] 33 3f [2] 28 39 [2] 34 3e [2] 28 11 }

  condition:
    any of them
}