rule TTP_XOR_QUAD_CurrentVersionRun_3bf7 {
  strings:
    $key_3bf7 = { 68 98 [2] 4c 96 [2] 67 ba [2] 49 98 [2] 5d 83 [2] 52 99 [2] 4c 84 [2] 4e 85 [2] 55 83 [2] 49 84 [2] 55 ab }

  condition:
    any of them
}