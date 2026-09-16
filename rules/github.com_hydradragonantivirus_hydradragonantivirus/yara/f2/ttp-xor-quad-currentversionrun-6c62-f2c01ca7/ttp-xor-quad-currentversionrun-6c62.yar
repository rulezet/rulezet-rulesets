rule TTP_XOR_QUAD_CurrentVersionRun_6c62 {
  strings:
    $key_6c62 = { 3f 0d [2] 1b 03 [2] 30 2f [2] 1e 0d [2] 0a 16 [2] 05 0c [2] 1b 11 [2] 19 10 [2] 02 16 [2] 1e 11 [2] 02 3e }

  condition:
    any of them
}