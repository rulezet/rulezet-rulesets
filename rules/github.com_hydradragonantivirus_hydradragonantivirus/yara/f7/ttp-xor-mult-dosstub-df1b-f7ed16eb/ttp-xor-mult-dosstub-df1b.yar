rule TTP_XOR_MULT_DOSStub_df1b {
  strings:
    $key_df1b = { 8b 73 [2] ff 6b [2] b8 69 [2] ff 78 [2] b1 74 [2] bd 7e [2] aa 75 [2] b1 3b [2] 8c }

  condition:
    any of them
}