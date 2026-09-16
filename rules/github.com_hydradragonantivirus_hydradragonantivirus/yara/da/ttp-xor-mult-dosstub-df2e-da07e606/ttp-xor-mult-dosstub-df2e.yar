rule TTP_XOR_MULT_DOSStub_df2e {
  strings:
    $key_df2e = { 8b 46 [2] ff 5e [2] b8 5c [2] ff 4d [2] b1 41 [2] bd 4b [2] aa 40 [2] b1 0e [2] 8c }

  condition:
    any of them
}