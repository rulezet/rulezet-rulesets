rule TTP_XOR_QUAD_CurrentVersionRun_4432 {
  strings:
    $key_4432 = { 17 5d [2] 33 53 [2] 18 7f [2] 36 5d [2] 22 46 [2] 2d 5c [2] 33 41 [2] 31 40 [2] 2a 46 [2] 36 41 [2] 2a 6e }

  condition:
    any of them
}