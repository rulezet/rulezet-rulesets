rule TTP_XOR_MULT_DOSStub_df28 {
  strings:
    $key_df28 = { 8b 40 [2] ff 58 [2] b8 5a [2] ff 4b [2] b1 47 [2] bd 4d [2] aa 46 [2] b1 08 [2] 8c }

  condition:
    any of them
}