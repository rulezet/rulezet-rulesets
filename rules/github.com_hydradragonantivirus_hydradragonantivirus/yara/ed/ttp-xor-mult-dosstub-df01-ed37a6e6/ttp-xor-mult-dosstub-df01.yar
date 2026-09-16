rule TTP_XOR_MULT_DOSStub_df01 {
  strings:
    $key_df01 = { 8b 69 [2] ff 71 [2] b8 73 [2] ff 62 [2] b1 6e [2] bd 64 [2] aa 6f [2] b1 21 [2] 8c }

  condition:
    any of them
}