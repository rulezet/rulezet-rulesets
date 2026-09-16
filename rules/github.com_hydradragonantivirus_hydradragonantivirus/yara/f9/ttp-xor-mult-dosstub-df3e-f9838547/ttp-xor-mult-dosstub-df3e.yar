rule TTP_XOR_MULT_DOSStub_df3e {
  strings:
    $key_df3e = { 8b 56 [2] ff 4e [2] b8 4c [2] ff 5d [2] b1 51 [2] bd 5b [2] aa 50 [2] b1 1e [2] 8c }

  condition:
    any of them
}