rule TTP_XOR_QUAD_CurrentVersionRun_2462 {
  strings:
    $key_2462 = { 77 0d [2] 53 03 [2] 78 2f [2] 56 0d [2] 42 16 [2] 4d 0c [2] 53 11 [2] 51 10 [2] 4a 16 [2] 56 11 [2] 4a 3e }

  condition:
    any of them
}