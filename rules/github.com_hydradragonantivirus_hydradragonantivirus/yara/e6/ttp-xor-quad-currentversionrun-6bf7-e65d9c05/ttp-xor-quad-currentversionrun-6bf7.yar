rule TTP_XOR_QUAD_CurrentVersionRun_6bf7 {
  strings:
    $key_6bf7 = { 38 98 [2] 1c 96 [2] 37 ba [2] 19 98 [2] 0d 83 [2] 02 99 [2] 1c 84 [2] 1e 85 [2] 05 83 [2] 19 84 [2] 05 ab }

  condition:
    any of them
}