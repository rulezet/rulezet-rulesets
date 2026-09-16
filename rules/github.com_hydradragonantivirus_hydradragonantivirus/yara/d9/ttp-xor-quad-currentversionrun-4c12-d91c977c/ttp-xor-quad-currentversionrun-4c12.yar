rule TTP_XOR_QUAD_CurrentVersionRun_4c12 {
  strings:
    $key_4c12 = { 1f 7d [2] 3b 73 [2] 10 5f [2] 3e 7d [2] 2a 66 [2] 25 7c [2] 3b 61 [2] 39 60 [2] 22 66 [2] 3e 61 [2] 22 4e }

  condition:
    any of them
}