rule TTP_XOR_MULT_DOSStub_df41 {
  strings:
    $key_df41 = { 8b 29 [2] ff 31 [2] b8 33 [2] ff 22 [2] b1 2e [2] bd 24 [2] aa 2f [2] b1 61 [2] 8c }

  condition:
    any of them
}