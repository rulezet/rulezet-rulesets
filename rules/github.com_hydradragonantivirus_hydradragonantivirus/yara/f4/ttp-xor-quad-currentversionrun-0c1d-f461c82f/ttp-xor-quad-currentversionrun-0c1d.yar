rule TTP_XOR_QUAD_CurrentVersionRun_0c1d {
  strings:
    $key_0c1d = { 5f 72 [2] 7b 7c [2] 50 50 [2] 7e 72 [2] 6a 69 [2] 65 73 [2] 7b 6e [2] 79 6f [2] 62 69 [2] 7e 6e [2] 62 41 }

  condition:
    any of them
}