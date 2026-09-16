rule TTP_XOR_QUAD_CurrentVersionRun_6f22 {
  strings:
    $key_6f22 = { 3c 4d [2] 18 43 [2] 33 6f [2] 1d 4d [2] 09 56 [2] 06 4c [2] 18 51 [2] 1a 50 [2] 01 56 [2] 1d 51 [2] 01 7e }

  condition:
    any of them
}