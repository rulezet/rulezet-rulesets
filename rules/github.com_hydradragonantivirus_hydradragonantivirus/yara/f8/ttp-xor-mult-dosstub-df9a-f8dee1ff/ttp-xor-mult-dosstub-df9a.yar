rule TTP_XOR_MULT_DOSStub_df9a {
  strings:
    $key_df9a = { 8b f2 [2] ff ea [2] b8 e8 [2] ff f9 [2] b1 f5 [2] bd ff [2] aa f4 [2] b1 ba [2] 8c }

  condition:
    any of them
}