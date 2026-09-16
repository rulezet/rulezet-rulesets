rule TTP_XOR_MULT_DOSStub_df65 {
  strings:
    $key_df65 = { 8b 0d [2] ff 15 [2] b8 17 [2] ff 06 [2] b1 0a [2] bd 00 [2] aa 0b [2] b1 45 [2] 8c }

  condition:
    any of them
}