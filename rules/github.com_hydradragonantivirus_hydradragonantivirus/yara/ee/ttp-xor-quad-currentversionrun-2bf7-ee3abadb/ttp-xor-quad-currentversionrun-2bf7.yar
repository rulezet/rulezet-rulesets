rule TTP_XOR_QUAD_CurrentVersionRun_2bf7 {
  strings:
    $key_2bf7 = { 78 98 [2] 5c 96 [2] 77 ba [2] 59 98 [2] 4d 83 [2] 42 99 [2] 5c 84 [2] 5e 85 [2] 45 83 [2] 59 84 [2] 45 ab }

  condition:
    any of them
}