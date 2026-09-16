rule TTP_XOR_QUAD_CurrentVersionRun_2d1d {
  strings:
    $key_2d1d = { 7e 72 [2] 5a 7c [2] 71 50 [2] 5f 72 [2] 4b 69 [2] 44 73 [2] 5a 6e [2] 58 6f [2] 43 69 [2] 5f 6e [2] 43 41 }

  condition:
    any of them
}