rule TTP_XOR_MULT_DOSStub_dfd1 {
  strings:
    $key_dfd1 = { 8b b9 [2] ff a1 [2] b8 a3 [2] ff b2 [2] b1 be [2] bd b4 [2] aa bf [2] b1 f1 [2] 8c }

  condition:
    any of them
}