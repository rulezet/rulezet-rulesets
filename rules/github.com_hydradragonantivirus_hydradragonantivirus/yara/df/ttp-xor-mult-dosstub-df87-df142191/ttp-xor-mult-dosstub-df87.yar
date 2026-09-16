rule TTP_XOR_MULT_DOSStub_df87 {
  strings:
    $key_df87 = { 8b ef [2] ff f7 [2] b8 f5 [2] ff e4 [2] b1 e8 [2] bd e2 [2] aa e9 [2] b1 a7 [2] 8c }

  condition:
    any of them
}