rule TTP_XOR_QUAD_CurrentVersionRun_6b4d {
  strings:
    $key_6b4d = { 38 22 [2] 1c 2c [2] 37 00 [2] 19 22 [2] 0d 39 [2] 02 23 [2] 1c 3e [2] 1e 3f [2] 05 39 [2] 19 3e [2] 05 11 }

  condition:
    any of them
}