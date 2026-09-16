rule TTP_XOR_QUAD_CurrentVersionRun_cda5 {
  strings:
    $key_cda5 = { 9e ca [2] ba c4 [2] 91 e8 [2] bf ca [2] ab d1 [2] a4 cb [2] ba d6 [2] b8 d7 [2] a3 d1 [2] bf d6 [2] a3 f9 }

  condition:
    any of them
}