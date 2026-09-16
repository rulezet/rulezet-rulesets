rule TTP_XOR_QUAD_CurrentVersionRun_31f7 {
  strings:
    $key_31f7 = { 62 98 [2] 46 96 [2] 6d ba [2] 43 98 [2] 57 83 [2] 58 99 [2] 46 84 [2] 44 85 [2] 5f 83 [2] 43 84 [2] 5f ab }

  condition:
    any of them
}