rule TTP_XOR_QUAD_CurrentVersionRun_4822 {
  strings:
    $key_4822 = { 1b 4d [2] 3f 43 [2] 14 6f [2] 3a 4d [2] 2e 56 [2] 21 4c [2] 3f 51 [2] 3d 50 [2] 26 56 [2] 3a 51 [2] 26 7e }

  condition:
    any of them
}