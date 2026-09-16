rule TTP_XOR_MULT_DOSStub_df7d {
  strings:
    $key_df7d = { 8b 15 [2] ff 0d [2] b8 0f [2] ff 1e [2] b1 12 [2] bd 18 [2] aa 13 [2] b1 5d [2] 8c }

  condition:
    any of them
}