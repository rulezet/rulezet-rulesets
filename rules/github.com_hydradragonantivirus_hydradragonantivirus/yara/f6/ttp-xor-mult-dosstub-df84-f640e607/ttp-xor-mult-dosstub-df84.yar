rule TTP_XOR_MULT_DOSStub_df84 {
  strings:
    $key_df84 = { 8b ec [2] ff f4 [2] b8 f6 [2] ff e7 [2] b1 eb [2] bd e1 [2] aa ea [2] b1 a4 [2] 8c }

  condition:
    any of them
}