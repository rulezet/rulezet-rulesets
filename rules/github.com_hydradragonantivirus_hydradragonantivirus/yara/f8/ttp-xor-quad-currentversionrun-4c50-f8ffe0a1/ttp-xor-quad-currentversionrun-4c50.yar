rule TTP_XOR_QUAD_CurrentVersionRun_4c50 {
  strings:
    $key_4c50 = { 1f 3f [2] 3b 31 [2] 10 1d [2] 3e 3f [2] 2a 24 [2] 25 3e [2] 3b 23 [2] 39 22 [2] 22 24 [2] 3e 23 [2] 22 0c }

  condition:
    any of them
}