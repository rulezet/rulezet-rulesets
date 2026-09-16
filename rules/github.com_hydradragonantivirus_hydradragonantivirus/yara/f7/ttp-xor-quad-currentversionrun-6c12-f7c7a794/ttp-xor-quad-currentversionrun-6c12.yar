rule TTP_XOR_QUAD_CurrentVersionRun_6c12 {
  strings:
    $key_6c12 = { 3f 7d [2] 1b 73 [2] 30 5f [2] 1e 7d [2] 0a 66 [2] 05 7c [2] 1b 61 [2] 19 60 [2] 02 66 [2] 1e 61 [2] 02 4e }

  condition:
    any of them
}