rule TTP_XOR_QUAD_CurrentVersionRun_1c1d {
  strings:
    $key_1c1d = { 4f 72 [2] 6b 7c [2] 40 50 [2] 6e 72 [2] 7a 69 [2] 75 73 [2] 6b 6e [2] 69 6f [2] 72 69 [2] 6e 6e [2] 72 41 }

  condition:
    any of them
}