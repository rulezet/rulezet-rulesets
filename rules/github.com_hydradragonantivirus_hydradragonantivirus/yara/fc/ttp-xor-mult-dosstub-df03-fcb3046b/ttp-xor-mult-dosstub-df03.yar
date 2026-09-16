rule TTP_XOR_MULT_DOSStub_df03 {
  strings:
    $key_df03 = { 8b 6b [2] ff 73 [2] b8 71 [2] ff 60 [2] b1 6c [2] bd 66 [2] aa 6d [2] b1 23 [2] 8c }

  condition:
    any of them
}