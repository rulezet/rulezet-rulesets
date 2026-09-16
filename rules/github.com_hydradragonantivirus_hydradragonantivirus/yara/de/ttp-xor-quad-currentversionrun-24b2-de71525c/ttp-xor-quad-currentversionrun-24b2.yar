rule TTP_XOR_QUAD_CurrentVersionRun_24b2 {
  strings:
    $key_24b2 = { 77 dd [2] 53 d3 [2] 78 ff [2] 56 dd [2] 42 c6 [2] 4d dc [2] 53 c1 [2] 51 c0 [2] 4a c6 [2] 56 c1 [2] 4a ee }

  condition:
    any of them
}