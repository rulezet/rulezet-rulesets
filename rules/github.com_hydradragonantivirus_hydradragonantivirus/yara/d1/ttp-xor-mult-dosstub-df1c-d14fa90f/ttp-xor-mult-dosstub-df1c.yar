rule TTP_XOR_MULT_DOSStub_df1c {
  strings:
    $key_df1c = { 8b 74 [2] ff 6c [2] b8 6e [2] ff 7f [2] b1 73 [2] bd 79 [2] aa 72 [2] b1 3c [2] 8c }

  condition:
    any of them
}