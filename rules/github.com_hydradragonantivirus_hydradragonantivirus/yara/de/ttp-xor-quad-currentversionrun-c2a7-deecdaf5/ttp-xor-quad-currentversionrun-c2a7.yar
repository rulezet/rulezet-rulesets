rule TTP_XOR_QUAD_CurrentVersionRun_c2a7 {
  strings:
    $key_c2a7 = { 91 c8 [2] b5 c6 [2] 9e ea [2] b0 c8 [2] a4 d3 [2] ab c9 [2] b5 d4 [2] b7 d5 [2] ac d3 [2] b0 d4 [2] ac fb }

  condition:
    any of them
}