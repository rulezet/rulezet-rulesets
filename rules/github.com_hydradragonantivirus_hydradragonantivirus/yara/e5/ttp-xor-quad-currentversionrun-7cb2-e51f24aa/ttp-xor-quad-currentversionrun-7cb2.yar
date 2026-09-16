rule TTP_XOR_QUAD_CurrentVersionRun_7cb2 {
  strings:
    $key_7cb2 = { 2f dd [2] 0b d3 [2] 20 ff [2] 0e dd [2] 1a c6 [2] 15 dc [2] 0b c1 [2] 09 c0 [2] 12 c6 [2] 0e c1 [2] 12 ee }

  condition:
    any of them
}