rule TTP_XOR_MULT_DOSStub_dfd2 {
  strings:
    $key_dfd2 = { 8b ba [2] ff a2 [2] b8 a0 [2] ff b1 [2] b1 bd [2] bd b7 [2] aa bc [2] b1 f2 [2] 8c }

  condition:
    any of them
}