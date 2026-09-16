rule TTP_XOR_QUAD_CurrentVersionRun_72f7 {
  strings:
    $key_72f7 = { 21 98 [2] 05 96 [2] 2e ba [2] 00 98 [2] 14 83 [2] 1b 99 [2] 05 84 [2] 07 85 [2] 1c 83 [2] 00 84 [2] 1c ab }

  condition:
    any of them
}