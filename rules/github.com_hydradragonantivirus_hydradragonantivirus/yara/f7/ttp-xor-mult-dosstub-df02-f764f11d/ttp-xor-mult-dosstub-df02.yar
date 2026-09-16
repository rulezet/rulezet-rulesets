rule TTP_XOR_MULT_DOSStub_df02 {
  strings:
    $key_df02 = { 8b 6a [2] ff 72 [2] b8 70 [2] ff 61 [2] b1 6d [2] bd 67 [2] aa 6c [2] b1 22 [2] 8c }

  condition:
    any of them
}