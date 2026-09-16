rule TTP_XOR_MULT_DOSStub_df04 {
  strings:
    $key_df04 = { 8b 6c [2] ff 74 [2] b8 76 [2] ff 67 [2] b1 6b [2] bd 61 [2] aa 6a [2] b1 24 [2] 8c }

  condition:
    any of them
}