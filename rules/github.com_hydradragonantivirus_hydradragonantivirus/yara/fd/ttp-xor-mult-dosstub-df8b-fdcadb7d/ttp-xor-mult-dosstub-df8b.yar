rule TTP_XOR_MULT_DOSStub_df8b {
  strings:
    $key_df8b = { 8b e3 [2] ff fb [2] b8 f9 [2] ff e8 [2] b1 e4 [2] bd ee [2] aa e5 [2] b1 ab [2] 8c }

  condition:
    any of them
}