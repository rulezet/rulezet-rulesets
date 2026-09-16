rule TTP_XOR_QUAD_CurrentVersionRun_6c4c {
  strings:
    $key_6c4c = { 3f 23 [2] 1b 2d [2] 30 01 [2] 1e 23 [2] 0a 38 [2] 05 22 [2] 1b 3f [2] 19 3e [2] 02 38 [2] 1e 3f [2] 02 10 }

  condition:
    any of them
}