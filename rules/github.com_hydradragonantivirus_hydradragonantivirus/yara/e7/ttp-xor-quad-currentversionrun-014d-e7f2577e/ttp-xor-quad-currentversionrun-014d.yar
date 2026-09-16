rule TTP_XOR_QUAD_CurrentVersionRun_014d {
  strings:
    $key_014d = { 52 22 [2] 76 2c [2] 5d 00 [2] 73 22 [2] 67 39 [2] 68 23 [2] 76 3e [2] 74 3f [2] 6f 39 [2] 73 3e [2] 6f 11 }

  condition:
    any of them
}