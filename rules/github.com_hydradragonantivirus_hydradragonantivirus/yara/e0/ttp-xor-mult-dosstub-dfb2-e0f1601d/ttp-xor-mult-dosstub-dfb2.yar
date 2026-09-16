rule TTP_XOR_MULT_DOSStub_dfb2 {
  strings:
    $key_dfb2 = { 8b da [2] ff c2 [2] b8 c0 [2] ff d1 [2] b1 dd [2] bd d7 [2] aa dc [2] b1 92 [2] 8c }

  condition:
    any of them
}