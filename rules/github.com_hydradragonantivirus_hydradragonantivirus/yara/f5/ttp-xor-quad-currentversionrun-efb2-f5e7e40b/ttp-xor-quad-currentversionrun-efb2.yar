rule TTP_XOR_QUAD_CurrentVersionRun_efb2 {
  strings:
    $key_efb2 = { bc dd [2] 98 d3 [2] b3 ff [2] 9d dd [2] 89 c6 [2] 86 dc [2] 98 c1 [2] 9a c0 [2] 81 c6 [2] 9d c1 [2] 81 ee }

  condition:
    any of them
}