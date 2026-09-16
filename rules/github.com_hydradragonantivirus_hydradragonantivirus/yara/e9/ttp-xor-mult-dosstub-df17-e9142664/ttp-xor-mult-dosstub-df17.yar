rule TTP_XOR_MULT_DOSStub_df17 {
  strings:
    $key_df17 = { 8b 7f [2] ff 67 [2] b8 65 [2] ff 74 [2] b1 78 [2] bd 72 [2] aa 79 [2] b1 37 [2] 8c }

  condition:
    any of them
}