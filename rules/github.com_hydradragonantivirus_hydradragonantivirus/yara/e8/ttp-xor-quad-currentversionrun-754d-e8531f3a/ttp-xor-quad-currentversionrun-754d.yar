rule TTP_XOR_QUAD_CurrentVersionRun_754d {
  strings:
    $key_754d = { 26 22 [2] 02 2c [2] 29 00 [2] 07 22 [2] 13 39 [2] 1c 23 [2] 02 3e [2] 00 3f [2] 1b 39 [2] 07 3e [2] 1b 11 }

  condition:
    any of them
}