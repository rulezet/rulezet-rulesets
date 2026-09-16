rule TTP_XOR_QUAD_CurrentVersionRun_3c63 {
  strings:
    $key_3c63 = { 6f 0c [2] 4b 02 [2] 60 2e [2] 4e 0c [2] 5a 17 [2] 55 0d [2] 4b 10 [2] 49 11 [2] 52 17 [2] 4e 10 [2] 52 3f }

  condition:
    any of them
}