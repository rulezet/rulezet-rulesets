rule TTP_XOR_QUAD_CurrentVersionRun_13b2 {
  strings:
    $key_13b2 = { 40 dd [2] 64 d3 [2] 4f ff [2] 61 dd [2] 75 c6 [2] 7a dc [2] 64 c1 [2] 66 c0 [2] 7d c6 [2] 61 c1 [2] 7d ee }

  condition:
    any of them
}