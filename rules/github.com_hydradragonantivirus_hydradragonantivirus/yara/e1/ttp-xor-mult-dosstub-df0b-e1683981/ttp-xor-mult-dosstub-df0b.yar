rule TTP_XOR_MULT_DOSStub_df0b {
  strings:
    $key_df0b = { 8b 63 [2] ff 7b [2] b8 79 [2] ff 68 [2] b1 64 [2] bd 6e [2] aa 65 [2] b1 2b [2] 8c }

  condition:
    any of them
}