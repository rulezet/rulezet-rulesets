rule TTP_XOR_QUAD_CurrentVersionRun_0c50 {
  strings:
    $key_0c50 = { 5f 3f [2] 7b 31 [2] 50 1d [2] 7e 3f [2] 6a 24 [2] 65 3e [2] 7b 23 [2] 79 22 [2] 62 24 [2] 7e 23 [2] 62 0c }

  condition:
    any of them
}