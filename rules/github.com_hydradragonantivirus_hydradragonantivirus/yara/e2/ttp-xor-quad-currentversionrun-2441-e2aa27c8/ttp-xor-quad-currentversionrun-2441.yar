rule TTP_XOR_QUAD_CurrentVersionRun_2441 {
  strings:
    $key_2441 = { 77 2e [2] 53 20 [2] 78 0c [2] 56 2e [2] 42 35 [2] 4d 2f [2] 53 32 [2] 51 33 [2] 4a 35 [2] 56 32 [2] 4a 1d }

  condition:
    any of them
}