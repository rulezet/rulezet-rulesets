rule TTP_XOR_QUAD_CurrentVersionRun_4462 {
  strings:
    $key_4462 = { 17 0d [2] 33 03 [2] 18 2f [2] 36 0d [2] 22 16 [2] 2d 0c [2] 33 11 [2] 31 10 [2] 2a 16 [2] 36 11 [2] 2a 3e }

  condition:
    any of them
}