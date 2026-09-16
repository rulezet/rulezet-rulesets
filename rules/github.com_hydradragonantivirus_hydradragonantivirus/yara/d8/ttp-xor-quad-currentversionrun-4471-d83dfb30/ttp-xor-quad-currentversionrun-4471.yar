rule TTP_XOR_QUAD_CurrentVersionRun_4471 {
  strings:
    $key_4471 = { 17 1e [2] 33 10 [2] 18 3c [2] 36 1e [2] 22 05 [2] 2d 1f [2] 33 02 [2] 31 03 [2] 2a 05 [2] 36 02 [2] 2a 2d }

  condition:
    any of them
}