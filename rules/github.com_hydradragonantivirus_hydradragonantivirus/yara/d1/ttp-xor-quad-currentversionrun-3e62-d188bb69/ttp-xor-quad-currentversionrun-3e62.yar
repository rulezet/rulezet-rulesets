rule TTP_XOR_QUAD_CurrentVersionRun_3e62 {
  strings:
    $key_3e62 = { 6d 0d [2] 49 03 [2] 62 2f [2] 4c 0d [2] 58 16 [2] 57 0c [2] 49 11 [2] 4b 10 [2] 50 16 [2] 4c 11 [2] 50 3e }

  condition:
    any of them
}