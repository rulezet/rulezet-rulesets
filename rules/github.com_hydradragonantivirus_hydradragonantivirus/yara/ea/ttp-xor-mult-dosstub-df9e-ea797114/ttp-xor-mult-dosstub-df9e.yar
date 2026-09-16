rule TTP_XOR_MULT_DOSStub_df9e {
  strings:
    $key_df9e = { 8b f6 [2] ff ee [2] b8 ec [2] ff fd [2] b1 f1 [2] bd fb [2] aa f0 [2] b1 be [2] 8c }

  condition:
    any of them
}