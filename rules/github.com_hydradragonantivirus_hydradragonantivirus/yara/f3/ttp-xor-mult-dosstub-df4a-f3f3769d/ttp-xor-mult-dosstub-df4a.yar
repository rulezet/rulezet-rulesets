rule TTP_XOR_MULT_DOSStub_df4a {
  strings:
    $key_df4a = { 8b 22 [2] ff 3a [2] b8 38 [2] ff 29 [2] b1 25 [2] bd 2f [2] aa 24 [2] b1 6a [2] 8c }

  condition:
    any of them
}