rule TTP_XOR_MULT_DOSStub_df95 {
  strings:
    $key_df95 = { 8b fd [2] ff e5 [2] b8 e7 [2] ff f6 [2] b1 fa [2] bd f0 [2] aa fb [2] b1 b5 [2] 8c }

  condition:
    any of them
}