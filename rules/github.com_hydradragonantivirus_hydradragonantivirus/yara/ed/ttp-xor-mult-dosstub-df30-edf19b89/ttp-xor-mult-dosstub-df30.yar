rule TTP_XOR_MULT_DOSStub_df30 {
  strings:
    $key_df30 = { 8b 58 [2] ff 40 [2] b8 42 [2] ff 53 [2] b1 5f [2] bd 55 [2] aa 5e [2] b1 10 [2] 8c }

  condition:
    any of them
}