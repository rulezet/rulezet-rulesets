rule TTP_XOR_MULT_DOSStub_df6d {
  strings:
    $key_df6d = { 8b 05 [2] ff 1d [2] b8 1f [2] ff 0e [2] b1 02 [2] bd 08 [2] aa 03 [2] b1 4d [2] 8c }

  condition:
    any of them
}