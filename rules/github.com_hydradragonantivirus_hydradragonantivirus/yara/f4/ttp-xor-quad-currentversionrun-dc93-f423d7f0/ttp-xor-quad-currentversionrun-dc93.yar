rule TTP_XOR_QUAD_CurrentVersionRun_dc93 {
  strings:
    $key_dc93 = { 8f fc [2] ab f2 [2] 80 de [2] ae fc [2] ba e7 [2] b5 fd [2] ab e0 [2] a9 e1 [2] b2 e7 [2] ae e0 [2] b2 cf }

  condition:
    any of them
}