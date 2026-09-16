rule TTP_XOR_QUAD_CurrentVersionRun_e706 {
  strings:
    $key_e706 = { b4 69 [2] 90 67 [2] bb 4b [2] 95 69 [2] 81 72 [2] 8e 68 [2] 90 75 [2] 92 74 [2] 89 72 [2] 95 75 [2] 89 5a }

  condition:
    any of them
}