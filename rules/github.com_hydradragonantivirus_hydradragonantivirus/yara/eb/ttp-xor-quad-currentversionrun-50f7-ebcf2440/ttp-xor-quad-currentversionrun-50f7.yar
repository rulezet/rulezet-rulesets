rule TTP_XOR_QUAD_CurrentVersionRun_50f7 {
  strings:
    $key_50f7 = { 03 98 [2] 27 96 [2] 0c ba [2] 22 98 [2] 36 83 [2] 39 99 [2] 27 84 [2] 25 85 [2] 3e 83 [2] 22 84 [2] 3e ab }

  condition:
    any of them
}