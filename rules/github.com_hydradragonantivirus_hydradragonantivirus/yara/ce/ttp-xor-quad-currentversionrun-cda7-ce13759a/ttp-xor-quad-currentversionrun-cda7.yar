rule TTP_XOR_QUAD_CurrentVersionRun_cda7 {
  strings:
    $key_cda7 = { 9e c8 [2] ba c6 [2] 91 ea [2] bf c8 [2] ab d3 [2] a4 c9 [2] ba d4 [2] b8 d5 [2] a3 d3 [2] bf d4 [2] a3 fb }

  condition:
    any of them
}