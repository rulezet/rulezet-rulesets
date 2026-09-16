rule TTP_XOR_MULT_DOSStub_df67 {
  strings:
    $key_df67 = { 8b 0f [2] ff 17 [2] b8 15 [2] ff 04 [2] b1 08 [2] bd 02 [2] aa 09 [2] b1 47 [2] 8c }

  condition:
    any of them
}