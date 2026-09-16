rule TTP_XOR_MULT_DOSStub_df32 {
  strings:
    $key_df32 = { 8b 5a [2] ff 42 [2] b8 40 [2] ff 51 [2] b1 5d [2] bd 57 [2] aa 5c [2] b1 12 [2] 8c }

  condition:
    any of them
}