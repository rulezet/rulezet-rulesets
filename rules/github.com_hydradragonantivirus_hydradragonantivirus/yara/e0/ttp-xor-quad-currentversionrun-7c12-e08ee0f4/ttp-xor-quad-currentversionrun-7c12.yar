rule TTP_XOR_QUAD_CurrentVersionRun_7c12 {
  strings:
    $key_7c12 = { 2f 7d [2] 0b 73 [2] 20 5f [2] 0e 7d [2] 1a 66 [2] 15 7c [2] 0b 61 [2] 09 60 [2] 12 66 [2] 0e 61 [2] 12 4e }

  condition:
    any of them
}