rule TTP_XOR_MULT_DOSStub_df5e {
  strings:
    $key_df5e = { 8b 36 [2] ff 2e [2] b8 2c [2] ff 3d [2] b1 31 [2] bd 3b [2] aa 30 [2] b1 7e [2] 8c }

  condition:
    any of them
}