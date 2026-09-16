rule TTP_XOR_QUAD_CurrentVersionRun_3df7 {
  strings:
    $key_3df7 = { 6e 98 [2] 4a 96 [2] 61 ba [2] 4f 98 [2] 5b 83 [2] 54 99 [2] 4a 84 [2] 48 85 [2] 53 83 [2] 4f 84 [2] 53 ab }

  condition:
    any of them
}