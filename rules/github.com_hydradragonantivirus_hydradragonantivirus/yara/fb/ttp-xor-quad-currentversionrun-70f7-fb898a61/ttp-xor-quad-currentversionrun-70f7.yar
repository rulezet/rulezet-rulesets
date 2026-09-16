rule TTP_XOR_QUAD_CurrentVersionRun_70f7 {
  strings:
    $key_70f7 = { 23 98 [2] 07 96 [2] 2c ba [2] 02 98 [2] 16 83 [2] 19 99 [2] 07 84 [2] 05 85 [2] 1e 83 [2] 02 84 [2] 1e ab }

  condition:
    any of them
}