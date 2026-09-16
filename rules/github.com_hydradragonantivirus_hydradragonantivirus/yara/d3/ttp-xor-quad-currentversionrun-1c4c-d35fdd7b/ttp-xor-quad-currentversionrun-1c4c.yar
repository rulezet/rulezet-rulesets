rule TTP_XOR_QUAD_CurrentVersionRun_1c4c {
  strings:
    $key_1c4c = { 4f 23 [2] 6b 2d [2] 40 01 [2] 6e 23 [2] 7a 38 [2] 75 22 [2] 6b 3f [2] 69 3e [2] 72 38 [2] 6e 3f [2] 72 10 }

  condition:
    any of them
}