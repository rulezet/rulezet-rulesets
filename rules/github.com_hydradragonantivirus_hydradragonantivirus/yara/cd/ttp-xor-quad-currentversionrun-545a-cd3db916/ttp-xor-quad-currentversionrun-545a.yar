rule TTP_XOR_QUAD_CurrentVersionRun_545a {
  strings:
    $key_545a = { 07 35 [2] 23 3b [2] 08 17 [2] 26 35 [2] 32 2e [2] 3d 34 [2] 23 29 [2] 21 28 [2] 3a 2e [2] 26 29 [2] 3a 06 }

  condition:
    any of them
}