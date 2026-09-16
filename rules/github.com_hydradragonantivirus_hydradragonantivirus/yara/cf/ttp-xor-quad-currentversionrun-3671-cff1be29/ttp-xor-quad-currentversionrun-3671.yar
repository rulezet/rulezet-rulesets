rule TTP_XOR_QUAD_CurrentVersionRun_3671 {
  strings:
    $key_3671 = { 65 1e [2] 41 10 [2] 6a 3c [2] 44 1e [2] 50 05 [2] 5f 1f [2] 41 02 [2] 43 03 [2] 58 05 [2] 44 02 [2] 58 2d }

  condition:
    any of them
}