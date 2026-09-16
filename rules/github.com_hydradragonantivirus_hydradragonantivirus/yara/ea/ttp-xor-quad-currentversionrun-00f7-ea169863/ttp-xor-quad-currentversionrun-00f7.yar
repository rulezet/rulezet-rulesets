rule TTP_XOR_QUAD_CurrentVersionRun_00f7 {
  strings:
    $key_00f7 = { 53 98 [2] 77 96 [2] 5c ba [2] 72 98 [2] 66 83 [2] 69 99 [2] 77 84 [2] 75 85 [2] 6e 83 [2] 72 84 [2] 6e ab }

  condition:
    any of them
}