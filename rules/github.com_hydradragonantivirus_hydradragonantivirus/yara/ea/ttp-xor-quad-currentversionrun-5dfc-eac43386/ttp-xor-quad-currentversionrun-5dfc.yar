rule TTP_XOR_QUAD_CurrentVersionRun_5dfc {
  strings:
    $key_5dfc = { 0e 93 [2] 2a 9d [2] 01 b1 [2] 2f 93 [2] 3b 88 [2] 34 92 [2] 2a 8f [2] 28 8e [2] 33 88 [2] 2f 8f [2] 33 a0 }

  condition:
    any of them
}