rule TTP_XOR_QUAD_CurrentVersionRun_73f7 {
  strings:
    $key_73f7 = { 20 98 [2] 04 96 [2] 2f ba [2] 01 98 [2] 15 83 [2] 1a 99 [2] 04 84 [2] 06 85 [2] 1d 83 [2] 01 84 [2] 1d ab }

  condition:
    any of them
}