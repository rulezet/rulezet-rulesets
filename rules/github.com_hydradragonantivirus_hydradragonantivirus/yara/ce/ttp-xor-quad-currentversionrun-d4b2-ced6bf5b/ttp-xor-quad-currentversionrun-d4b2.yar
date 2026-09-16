rule TTP_XOR_QUAD_CurrentVersionRun_d4b2 {
  strings:
    $key_d4b2 = { 87 dd [2] a3 d3 [2] 88 ff [2] a6 dd [2] b2 c6 [2] bd dc [2] a3 c1 [2] a1 c0 [2] ba c6 [2] a6 c1 [2] ba ee }

  condition:
    any of them
}