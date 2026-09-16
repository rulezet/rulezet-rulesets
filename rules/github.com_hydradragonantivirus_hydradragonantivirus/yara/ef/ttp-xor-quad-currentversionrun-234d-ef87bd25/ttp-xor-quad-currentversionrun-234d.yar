rule TTP_XOR_QUAD_CurrentVersionRun_234d {
  strings:
    $key_234d = { 70 22 [2] 54 2c [2] 7f 00 [2] 51 22 [2] 45 39 [2] 4a 23 [2] 54 3e [2] 56 3f [2] 4d 39 [2] 51 3e [2] 4d 11 }

  condition:
    any of them
}