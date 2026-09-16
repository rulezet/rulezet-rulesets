rule TTP_XOR_MULT_DOSStub_cbb2 {
  strings:
    $key_cbb2 = { 9f da [2] eb c2 [2] ac c0 [2] eb d1 [2] a5 dd [2] a9 d7 [2] be dc [2] a5 92 [2] 98 }

  condition:
    any of them
}