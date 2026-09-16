rule TTP_XOR_MULT_DOSStub_df54 {
  strings:
    $key_df54 = { 8b 3c [2] ff 24 [2] b8 26 [2] ff 37 [2] b1 3b [2] bd 31 [2] aa 3a [2] b1 74 [2] 8c }

  condition:
    any of them
}