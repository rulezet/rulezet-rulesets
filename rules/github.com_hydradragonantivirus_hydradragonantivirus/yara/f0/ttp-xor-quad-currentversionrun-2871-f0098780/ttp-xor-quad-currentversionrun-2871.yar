rule TTP_XOR_QUAD_CurrentVersionRun_2871 {
  strings:
    $key_2871 = { 7b 1e [2] 5f 10 [2] 74 3c [2] 5a 1e [2] 4e 05 [2] 41 1f [2] 5f 02 [2] 5d 03 [2] 46 05 [2] 5a 02 [2] 46 2d }

  condition:
    any of them
}