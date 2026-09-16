rule TTP_XOR_MULT_DOSStub_df1e {
  strings:
    $key_df1e = { 8b 76 [2] ff 6e [2] b8 6c [2] ff 7d [2] b1 71 [2] bd 7b [2] aa 70 [2] b1 3e [2] 8c }

  condition:
    any of them
}