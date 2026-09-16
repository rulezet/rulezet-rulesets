rule TTP_XOR_QUAD_CurrentVersionRun_5d2d {
  strings:
    $key_5d2d = { 0e 42 [2] 2a 4c [2] 01 60 [2] 2f 42 [2] 3b 59 [2] 34 43 [2] 2a 5e [2] 28 5f [2] 33 59 [2] 2f 5e [2] 33 71 }

  condition:
    any of them
}