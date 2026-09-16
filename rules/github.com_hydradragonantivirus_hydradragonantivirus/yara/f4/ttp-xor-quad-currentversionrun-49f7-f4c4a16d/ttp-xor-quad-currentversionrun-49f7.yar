rule TTP_XOR_QUAD_CurrentVersionRun_49f7 {
  strings:
    $key_49f7 = { 1a 98 [2] 3e 96 [2] 15 ba [2] 3b 98 [2] 2f 83 [2] 20 99 [2] 3e 84 [2] 3c 85 [2] 27 83 [2] 3b 84 [2] 27 ab }

  condition:
    any of them
}