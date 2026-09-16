rule TTP_XOR_MULT_DOSStub_df43 {
  strings:
    $key_df43 = { 8b 2b [2] ff 33 [2] b8 31 [2] ff 20 [2] b1 2c [2] bd 26 [2] aa 2d [2] b1 63 [2] 8c }

  condition:
    any of them
}