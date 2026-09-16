rule TTP_XOR_QUAD_CurrentVersionRun_c2b1 {
  strings:
    $key_c2b1 = { 91 de [2] b5 d0 [2] 9e fc [2] b0 de [2] a4 c5 [2] ab df [2] b5 c2 [2] b7 c3 [2] ac c5 [2] b0 c2 [2] ac ed }

  condition:
    any of them
}