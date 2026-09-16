rule TTP_XOR_QUAD_CurrentVersionRun_254d {
  strings:
    $key_254d = { 76 22 [2] 52 2c [2] 79 00 [2] 57 22 [2] 43 39 [2] 4c 23 [2] 52 3e [2] 50 3f [2] 4b 39 [2] 57 3e [2] 4b 11 }

  condition:
    any of them
}