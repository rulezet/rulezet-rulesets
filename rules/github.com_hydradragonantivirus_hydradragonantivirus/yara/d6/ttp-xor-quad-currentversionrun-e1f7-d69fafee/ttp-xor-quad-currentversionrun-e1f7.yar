rule TTP_XOR_QUAD_CurrentVersionRun_e1f7 {
  strings:
    $key_e1f7 = { b2 98 [2] 96 96 [2] bd ba [2] 93 98 [2] 87 83 [2] 88 99 [2] 96 84 [2] 94 85 [2] 8f 83 [2] 93 84 [2] 8f ab }

  condition:
    any of them
}