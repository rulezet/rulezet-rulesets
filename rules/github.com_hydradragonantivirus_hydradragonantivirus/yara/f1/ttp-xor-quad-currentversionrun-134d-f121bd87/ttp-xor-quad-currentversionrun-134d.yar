rule TTP_XOR_QUAD_CurrentVersionRun_134d {
  strings:
    $key_134d = { 40 22 [2] 64 2c [2] 4f 00 [2] 61 22 [2] 75 39 [2] 7a 23 [2] 64 3e [2] 66 3f [2] 7d 39 [2] 61 3e [2] 7d 11 }

  condition:
    any of them
}