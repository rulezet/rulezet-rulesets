rule TTP_XOR_MULT_DOSStub_df06 {
  strings:
    $key_df06 = { 8b 6e [2] ff 76 [2] b8 74 [2] ff 65 [2] b1 69 [2] bd 63 [2] aa 68 [2] b1 26 [2] 8c }

  condition:
    any of them
}