rule TTP_XOR_QUAD_CurrentVersionRun_cdb4 {
  strings:
    $key_cdb4 = { 9e db [2] ba d5 [2] 91 f9 [2] bf db [2] ab c0 [2] a4 da [2] ba c7 [2] b8 c6 [2] a3 c0 [2] bf c7 [2] a3 e8 }

  condition:
    any of them
}