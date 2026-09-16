rule TTP_XOR_QUAD_CurrentVersionRun_114d {
  strings:
    $key_114d = { 42 22 [2] 66 2c [2] 4d 00 [2] 63 22 [2] 77 39 [2] 78 23 [2] 66 3e [2] 64 3f [2] 7f 39 [2] 63 3e [2] 7f 11 }

  condition:
    any of them
}