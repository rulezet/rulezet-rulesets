rule TTP_XOR_MULT_DOSStub_dfd4 {
  strings:
    $key_dfd4 = { 8b bc [2] ff a4 [2] b8 a6 [2] ff b7 [2] b1 bb [2] bd b1 [2] aa ba [2] b1 f4 [2] 8c }

  condition:
    any of them
}