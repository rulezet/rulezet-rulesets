rule TTP_XOR_MULT_DOSStub_dfb1 {
  strings:
    $key_dfb1 = { 8b d9 [2] ff c1 [2] b8 c3 [2] ff d2 [2] b1 de [2] bd d4 [2] aa df [2] b1 91 [2] 8c }

  condition:
    any of them
}