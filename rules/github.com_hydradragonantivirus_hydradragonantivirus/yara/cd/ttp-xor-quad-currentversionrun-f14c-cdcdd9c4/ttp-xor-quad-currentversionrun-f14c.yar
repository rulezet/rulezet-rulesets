rule TTP_XOR_QUAD_CurrentVersionRun_f14c {
  strings:
    $key_f14c = { a2 23 [2] 86 2d [2] ad 01 [2] 83 23 [2] 97 38 [2] 98 22 [2] 86 3f [2] 84 3e [2] 9f 38 [2] 83 3f [2] 9f 10 }

  condition:
    any of them
}