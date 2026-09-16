rule TTP_XOR_MULT_DOSStub_df89 {
  strings:
    $key_df89 = { 8b e1 [2] ff f9 [2] b8 fb [2] ff ea [2] b1 e6 [2] bd ec [2] aa e7 [2] b1 a9 [2] 8c }

  condition:
    any of them
}