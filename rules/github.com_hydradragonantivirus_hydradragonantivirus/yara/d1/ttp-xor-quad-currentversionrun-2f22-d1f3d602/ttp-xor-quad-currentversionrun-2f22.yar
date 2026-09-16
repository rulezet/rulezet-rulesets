rule TTP_XOR_QUAD_CurrentVersionRun_2f22 {
  strings:
    $key_2f22 = { 7c 4d [2] 58 43 [2] 73 6f [2] 5d 4d [2] 49 56 [2] 46 4c [2] 58 51 [2] 5a 50 [2] 41 56 [2] 5d 51 [2] 41 7e }

  condition:
    any of them
}