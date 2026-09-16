rule TTP_XOR_QUAD_CurrentVersionRun_1a4d {
  strings:
    $key_1a4d = { 49 22 [2] 6d 2c [2] 46 00 [2] 68 22 [2] 7c 39 [2] 73 23 [2] 6d 3e [2] 6f 3f [2] 74 39 [2] 68 3e [2] 74 11 }

  condition:
    any of them
}