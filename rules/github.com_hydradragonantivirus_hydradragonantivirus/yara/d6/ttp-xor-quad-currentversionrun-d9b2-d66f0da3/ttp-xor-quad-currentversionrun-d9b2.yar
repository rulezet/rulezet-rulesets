rule TTP_XOR_QUAD_CurrentVersionRun_d9b2 {
  strings:
    $key_d9b2 = { 8a dd [2] ae d3 [2] 85 ff [2] ab dd [2] bf c6 [2] b0 dc [2] ae c1 [2] ac c0 [2] b7 c6 [2] ab c1 [2] b7 ee }

  condition:
    any of them
}