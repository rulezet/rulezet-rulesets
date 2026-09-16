rule TTP_XOR_MULT_DOSStub_df3d {
  strings:
    $key_df3d = { 8b 55 [2] ff 4d [2] b8 4f [2] ff 5e [2] b1 52 [2] bd 58 [2] aa 53 [2] b1 1d [2] 8c }

  condition:
    any of them
}