rule TTP_XOR_QUAD_CurrentVersionRun_3263 {
  strings:
    $key_3263 = { 61 0c [2] 45 02 [2] 6e 2e [2] 40 0c [2] 54 17 [2] 5b 0d [2] 45 10 [2] 47 11 [2] 5c 17 [2] 40 10 [2] 5c 3f }

  condition:
    any of them
}