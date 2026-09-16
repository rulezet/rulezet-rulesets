rule TTP_XOR_QUAD_CurrentVersionRun_2e63 {
  strings:
    $key_2e63 = { 7d 0c [2] 59 02 [2] 72 2e [2] 5c 0c [2] 48 17 [2] 47 0d [2] 59 10 [2] 5b 11 [2] 40 17 [2] 5c 10 [2] 40 3f }

  condition:
    any of them
}