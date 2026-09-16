rule TTP_XOR_QUAD_CurrentVersionRun_2371 {
  strings:
    $key_2371 = { 70 1e [2] 54 10 [2] 7f 3c [2] 51 1e [2] 45 05 [2] 4a 1f [2] 54 02 [2] 56 03 [2] 4d 05 [2] 51 02 [2] 4d 2d }

  condition:
    any of them
}