rule TTP_XOR_QUAD_CurrentVersionRun_7122 {
  strings:
    $key_7122 = { 22 4d [2] 06 43 [2] 2d 6f [2] 03 4d [2] 17 56 [2] 18 4c [2] 06 51 [2] 04 50 [2] 1f 56 [2] 03 51 [2] 1f 7e }

  condition:
    any of them
}