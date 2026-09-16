rule TTP_XOR_QUAD_CurrentVersionRun_62f7 {
  strings:
    $key_62f7 = { 31 98 [2] 15 96 [2] 3e ba [2] 10 98 [2] 04 83 [2] 0b 99 [2] 15 84 [2] 17 85 [2] 0c 83 [2] 10 84 [2] 0c ab }

  condition:
    any of them
}