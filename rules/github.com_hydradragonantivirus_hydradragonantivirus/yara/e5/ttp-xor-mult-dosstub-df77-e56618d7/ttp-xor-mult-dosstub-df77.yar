rule TTP_XOR_MULT_DOSStub_df77 {
  strings:
    $key_df77 = { 8b 1f [2] ff 07 [2] b8 05 [2] ff 14 [2] b1 18 [2] bd 12 [2] aa 19 [2] b1 57 [2] 8c }

  condition:
    any of them
}