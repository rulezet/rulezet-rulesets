rule TTP_XOR_QUAD_CurrentVersionRun_2f62 {
  strings:
    $key_2f62 = { 7c 0d [2] 58 03 [2] 73 2f [2] 5d 0d [2] 49 16 [2] 46 0c [2] 58 11 [2] 5a 10 [2] 41 16 [2] 5d 11 [2] 41 3e }

  condition:
    any of them
}