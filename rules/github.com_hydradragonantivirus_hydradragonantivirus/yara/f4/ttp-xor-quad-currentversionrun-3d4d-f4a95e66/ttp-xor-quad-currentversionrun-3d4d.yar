rule TTP_XOR_QUAD_CurrentVersionRun_3d4d {
  strings:
    $key_3d4d = { 6e 22 [2] 4a 2c [2] 61 00 [2] 4f 22 [2] 5b 39 [2] 54 23 [2] 4a 3e [2] 48 3f [2] 53 39 [2] 4f 3e [2] 53 11 }

  condition:
    any of them
}