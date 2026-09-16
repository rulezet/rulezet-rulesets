rule TTP_XOR_QUAD_CurrentVersionRun_4e22 {
  strings:
    $key_4e22 = { 1d 4d [2] 39 43 [2] 12 6f [2] 3c 4d [2] 28 56 [2] 27 4c [2] 39 51 [2] 3b 50 [2] 20 56 [2] 3c 51 [2] 20 7e }

  condition:
    any of them
}