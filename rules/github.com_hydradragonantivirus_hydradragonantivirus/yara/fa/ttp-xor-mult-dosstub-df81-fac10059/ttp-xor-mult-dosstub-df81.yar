rule TTP_XOR_MULT_DOSStub_df81 {
  strings:
    $key_df81 = { 8b e9 [2] ff f1 [2] b8 f3 [2] ff e2 [2] b1 ee [2] bd e4 [2] aa ef [2] b1 a1 [2] 8c }

  condition:
    any of them
}