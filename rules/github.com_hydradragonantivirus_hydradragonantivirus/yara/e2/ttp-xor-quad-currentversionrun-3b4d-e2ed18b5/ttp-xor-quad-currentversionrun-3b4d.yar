rule TTP_XOR_QUAD_CurrentVersionRun_3b4d {
  strings:
    $key_3b4d = { 68 22 [2] 4c 2c [2] 67 00 [2] 49 22 [2] 5d 39 [2] 52 23 [2] 4c 3e [2] 4e 3f [2] 55 39 [2] 49 3e [2] 55 11 }

  condition:
    any of them
}