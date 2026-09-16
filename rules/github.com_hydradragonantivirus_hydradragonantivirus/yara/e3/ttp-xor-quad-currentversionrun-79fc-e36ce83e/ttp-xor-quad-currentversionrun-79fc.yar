rule TTP_XOR_QUAD_CurrentVersionRun_79fc {
  strings:
    $key_79fc = { 2a 93 [2] 0e 9d [2] 25 b1 [2] 0b 93 [2] 1f 88 [2] 10 92 [2] 0e 8f [2] 0c 8e [2] 17 88 [2] 0b 8f [2] 17 a0 }

  condition:
    any of them
}