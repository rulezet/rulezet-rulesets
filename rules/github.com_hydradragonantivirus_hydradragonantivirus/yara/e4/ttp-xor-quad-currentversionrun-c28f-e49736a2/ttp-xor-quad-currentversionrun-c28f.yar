rule TTP_XOR_QUAD_CurrentVersionRun_c28f {
  strings:
    $key_c28f = { 91 e0 [2] b5 ee [2] 9e c2 [2] b0 e0 [2] a4 fb [2] ab e1 [2] b5 fc [2] b7 fd [2] ac fb [2] b0 fc [2] ac d3 }

  condition:
    any of them
}