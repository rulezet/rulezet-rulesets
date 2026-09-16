rule TTP_XOR_QUAD_CurrentVersionRun_2471 {
  strings:
    $key_2471 = { 77 1e [2] 53 10 [2] 78 3c [2] 56 1e [2] 42 05 [2] 4d 1f [2] 53 02 [2] 51 03 [2] 4a 05 [2] 56 02 [2] 4a 2d }

  condition:
    any of them
}