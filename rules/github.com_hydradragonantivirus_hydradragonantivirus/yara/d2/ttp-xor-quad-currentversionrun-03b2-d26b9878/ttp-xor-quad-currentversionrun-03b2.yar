rule TTP_XOR_QUAD_CurrentVersionRun_03b2 {
  strings:
    $key_03b2 = { 50 dd [2] 74 d3 [2] 5f ff [2] 71 dd [2] 65 c6 [2] 6a dc [2] 74 c1 [2] 76 c0 [2] 6d c6 [2] 71 c1 [2] 6d ee }

  condition:
    any of them
}