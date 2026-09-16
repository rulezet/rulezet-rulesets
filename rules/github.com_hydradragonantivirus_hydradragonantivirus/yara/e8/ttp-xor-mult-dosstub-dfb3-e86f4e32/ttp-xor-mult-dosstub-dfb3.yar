rule TTP_XOR_MULT_DOSStub_dfb3 {
  strings:
    $key_dfb3 = { 8b db [2] ff c3 [2] b8 c1 [2] ff d0 [2] b1 dc [2] bd d6 [2] aa dd [2] b1 93 [2] 8c }

  condition:
    any of them
}