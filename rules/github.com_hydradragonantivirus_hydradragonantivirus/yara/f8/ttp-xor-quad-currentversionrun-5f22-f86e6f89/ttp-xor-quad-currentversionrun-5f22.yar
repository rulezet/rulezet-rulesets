rule TTP_XOR_QUAD_CurrentVersionRun_5f22 {
  strings:
    $key_5f22 = { 0c 4d [2] 28 43 [2] 03 6f [2] 2d 4d [2] 39 56 [2] 36 4c [2] 28 51 [2] 2a 50 [2] 31 56 [2] 2d 51 [2] 31 7e }

  condition:
    any of them
}