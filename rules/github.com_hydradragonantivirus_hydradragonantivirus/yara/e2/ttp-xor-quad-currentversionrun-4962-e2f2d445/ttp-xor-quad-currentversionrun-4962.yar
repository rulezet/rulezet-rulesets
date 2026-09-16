rule TTP_XOR_QUAD_CurrentVersionRun_4962 {
  strings:
    $key_4962 = { 1a 0d [2] 3e 03 [2] 15 2f [2] 3b 0d [2] 2f 16 [2] 20 0c [2] 3e 11 [2] 3c 10 [2] 27 16 [2] 3b 11 [2] 27 3e }

  condition:
    any of them
}