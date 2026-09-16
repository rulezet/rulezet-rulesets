rule TTP_XOR_MULT_DOSStub_df3c {
  strings:
    $key_df3c = { 8b 54 [2] ff 4c [2] b8 4e [2] ff 5f [2] b1 53 [2] bd 59 [2] aa 52 [2] b1 1c [2] 8c }

  condition:
    any of them
}