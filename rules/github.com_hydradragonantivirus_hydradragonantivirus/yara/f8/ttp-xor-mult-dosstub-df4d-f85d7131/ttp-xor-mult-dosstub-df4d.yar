rule TTP_XOR_MULT_DOSStub_df4d {
  strings:
    $key_df4d = { 8b 25 [2] ff 3d [2] b8 3f [2] ff 2e [2] b1 22 [2] bd 28 [2] aa 23 [2] b1 6d [2] 8c }

  condition:
    any of them
}