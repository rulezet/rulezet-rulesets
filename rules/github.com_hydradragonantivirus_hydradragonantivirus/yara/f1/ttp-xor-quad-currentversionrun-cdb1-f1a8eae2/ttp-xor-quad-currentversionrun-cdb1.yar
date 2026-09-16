rule TTP_XOR_QUAD_CurrentVersionRun_cdb1 {
  strings:
    $key_cdb1 = { 9e de [2] ba d0 [2] 91 fc [2] bf de [2] ab c5 [2] a4 df [2] ba c2 [2] b8 c3 [2] a3 c5 [2] bf c2 [2] a3 ed }

  condition:
    any of them
}