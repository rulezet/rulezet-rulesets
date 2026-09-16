rule TTP_XOR_QUAD_CurrentVersionRun_2863 {
  strings:
    $key_2863 = { 7b 0c [2] 5f 02 [2] 74 2e [2] 5a 0c [2] 4e 17 [2] 41 0d [2] 5f 10 [2] 5d 11 [2] 46 17 [2] 5a 10 [2] 46 3f }

  condition:
    any of them
}