rule TTP_XOR_QUAD_CurrentVersionRun_6ff7 {
  strings:
    $key_6ff7 = { 3c 98 [2] 18 96 [2] 33 ba [2] 1d 98 [2] 09 83 [2] 06 99 [2] 18 84 [2] 1a 85 [2] 01 83 [2] 1d 84 [2] 01 ab }

  condition:
    any of them
}