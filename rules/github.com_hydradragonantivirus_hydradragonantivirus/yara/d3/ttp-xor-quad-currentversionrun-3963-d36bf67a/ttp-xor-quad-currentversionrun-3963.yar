rule TTP_XOR_QUAD_CurrentVersionRun_3963 {
  strings:
    $key_3963 = { 6a 0c [2] 4e 02 [2] 65 2e [2] 4b 0c [2] 5f 17 [2] 50 0d [2] 4e 10 [2] 4c 11 [2] 57 17 [2] 4b 10 [2] 57 3f }

  condition:
    any of them
}