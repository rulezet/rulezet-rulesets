rule TTP_XOR_QUAD_CurrentVersionRun_524c {
  strings:
    $key_524c = { 01 23 [2] 25 2d [2] 0e 01 [2] 20 23 [2] 34 38 [2] 3b 22 [2] 25 3f [2] 27 3e [2] 3c 38 [2] 20 3f [2] 3c 10 }

  condition:
    any of them
}