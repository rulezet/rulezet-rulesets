rule TTP_XOR_QUAD_CurrentVersionRun_d007 {
  strings:
    $key_d007 = { 83 68 [2] a7 66 [2] 8c 4a [2] a2 68 [2] b6 73 [2] b9 69 [2] a7 74 [2] a5 75 [2] be 73 [2] a2 74 [2] be 5b }

  condition:
    any of them
}