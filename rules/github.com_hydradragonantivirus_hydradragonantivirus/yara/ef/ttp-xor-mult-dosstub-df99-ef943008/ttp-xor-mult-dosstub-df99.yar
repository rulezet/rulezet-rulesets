rule TTP_XOR_MULT_DOSStub_df99 {
  strings:
    $key_df99 = { 8b f1 [2] ff e9 [2] b8 eb [2] ff fa [2] b1 f6 [2] bd fc [2] aa f7 [2] b1 b9 [2] 8c }

  condition:
    any of them
}