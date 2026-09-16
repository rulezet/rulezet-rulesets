rule TTP_XOR_QUAD_CurrentVersionRun_6c66 {
  strings:
    $key_6c66 = { 3f 09 [2] 1b 07 [2] 30 2b [2] 1e 09 [2] 0a 12 [2] 05 08 [2] 1b 15 [2] 19 14 [2] 02 12 [2] 1e 15 [2] 02 3a }

  condition:
    any of them
}