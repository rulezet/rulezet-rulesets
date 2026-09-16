rule TTP_XOR_QUAD_CurrentVersionRun_e9f7 {
  strings:
    $key_e9f7 = { ba 98 [2] 9e 96 [2] b5 ba [2] 9b 98 [2] 8f 83 [2] 80 99 [2] 9e 84 [2] 9c 85 [2] 87 83 [2] 9b 84 [2] 87 ab }

  condition:
    any of them
}