rule TTP_XOR_QUAD_CurrentVersionRun_5a21 {
  strings:
    $key_5a21 = { 09 4e [2] 2d 40 [2] 06 6c [2] 28 4e [2] 3c 55 [2] 33 4f [2] 2d 52 [2] 2f 53 [2] 34 55 [2] 28 52 [2] 34 7d }

  condition:
    any of them
}