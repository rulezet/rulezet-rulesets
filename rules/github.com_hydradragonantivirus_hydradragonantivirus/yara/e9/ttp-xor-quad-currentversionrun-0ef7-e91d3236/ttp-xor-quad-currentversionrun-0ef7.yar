rule TTP_XOR_QUAD_CurrentVersionRun_0ef7 {
  strings:
    $key_0ef7 = { 5d 98 [2] 79 96 [2] 52 ba [2] 7c 98 [2] 68 83 [2] 67 99 [2] 79 84 [2] 7b 85 [2] 60 83 [2] 7c 84 [2] 60 ab }

  condition:
    any of them
}