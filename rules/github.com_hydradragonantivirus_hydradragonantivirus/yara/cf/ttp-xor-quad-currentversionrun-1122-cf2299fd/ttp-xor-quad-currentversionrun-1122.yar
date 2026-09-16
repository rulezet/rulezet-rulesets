rule TTP_XOR_QUAD_CurrentVersionRun_1122 {
  strings:
    $key_1122 = { 42 4d [2] 66 43 [2] 4d 6f [2] 63 4d [2] 77 56 [2] 78 4c [2] 66 51 [2] 64 50 [2] 7f 56 [2] 63 51 [2] 7f 7e }

  condition:
    any of them
}