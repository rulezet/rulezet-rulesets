rule TTP_XOR_QUAD_CurrentVersionRun_3441 {
  strings:
    $key_3441 = { 67 2e [2] 43 20 [2] 68 0c [2] 46 2e [2] 52 35 [2] 5d 2f [2] 43 32 [2] 41 33 [2] 5a 35 [2] 46 32 [2] 5a 1d }

  condition:
    any of them
}