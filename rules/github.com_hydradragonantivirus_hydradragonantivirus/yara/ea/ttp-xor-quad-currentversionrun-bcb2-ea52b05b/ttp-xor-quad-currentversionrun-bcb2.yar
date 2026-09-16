rule TTP_XOR_QUAD_CurrentVersionRun_bcb2 {
  strings:
    $key_bcb2 = { ef dd [2] cb d3 [2] e0 ff [2] ce dd [2] da c6 [2] d5 dc [2] cb c1 [2] c9 c0 [2] d2 c6 [2] ce c1 [2] d2 ee }

  condition:
    any of them
}