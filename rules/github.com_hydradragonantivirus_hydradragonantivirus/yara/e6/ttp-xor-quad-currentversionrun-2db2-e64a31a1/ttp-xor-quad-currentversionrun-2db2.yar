rule TTP_XOR_QUAD_CurrentVersionRun_2db2 {
  strings:
    $key_2db2 = { 7e dd [2] 5a d3 [2] 71 ff [2] 5f dd [2] 4b c6 [2] 44 dc [2] 5a c1 [2] 58 c0 [2] 43 c6 [2] 5f c1 [2] 43 ee }

  condition:
    any of them
}