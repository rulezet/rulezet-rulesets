rule TTP_XOR_QUAD_CurrentVersionRun_41f7 {
  strings:
    $key_41f7 = { 12 98 [2] 36 96 [2] 1d ba [2] 33 98 [2] 27 83 [2] 28 99 [2] 36 84 [2] 34 85 [2] 2f 83 [2] 33 84 [2] 2f ab }

  condition:
    any of them
}