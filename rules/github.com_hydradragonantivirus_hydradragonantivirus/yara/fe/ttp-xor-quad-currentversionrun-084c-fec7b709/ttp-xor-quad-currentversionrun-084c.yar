rule TTP_XOR_QUAD_CurrentVersionRun_084c {
  strings:
    $key_084c = { 5b 23 [2] 7f 2d [2] 54 01 [2] 7a 23 [2] 6e 38 [2] 61 22 [2] 7f 3f [2] 7d 3e [2] 66 38 [2] 7a 3f [2] 66 10 }

  condition:
    any of them
}