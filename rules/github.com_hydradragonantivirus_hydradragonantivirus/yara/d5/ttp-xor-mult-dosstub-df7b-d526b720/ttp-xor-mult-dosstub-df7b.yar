rule TTP_XOR_MULT_DOSStub_df7b {
  strings:
    $key_df7b = { 8b 13 [2] ff 0b [2] b8 09 [2] ff 18 [2] b1 14 [2] bd 1e [2] aa 15 [2] b1 5b [2] 8c }

  condition:
    any of them
}