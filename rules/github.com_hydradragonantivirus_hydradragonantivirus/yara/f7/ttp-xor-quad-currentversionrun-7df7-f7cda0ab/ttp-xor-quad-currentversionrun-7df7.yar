rule TTP_XOR_QUAD_CurrentVersionRun_7df7 {
  strings:
    $key_7df7 = { 2e 98 [2] 0a 96 [2] 21 ba [2] 0f 98 [2] 1b 83 [2] 14 99 [2] 0a 84 [2] 08 85 [2] 13 83 [2] 0f 84 [2] 13 ab }

  condition:
    any of them
}