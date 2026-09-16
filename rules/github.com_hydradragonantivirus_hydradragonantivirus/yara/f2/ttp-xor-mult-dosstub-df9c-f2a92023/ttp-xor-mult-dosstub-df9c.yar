rule TTP_XOR_MULT_DOSStub_df9c {
  strings:
    $key_df9c = { 8b f4 [2] ff ec [2] b8 ee [2] ff ff [2] b1 f3 [2] bd f9 [2] aa f2 [2] b1 bc [2] 8c }

  condition:
    any of them
}