rule TTP_XOR_MULT_DOSStub_dfe4 {
  strings:
    $key_dfe4 = { 8b 8c [2] ff 94 [2] b8 96 [2] ff 87 [2] b1 8b [2] bd 81 [2] aa 8a [2] b1 c4 [2] 8c }

  condition:
    any of them
}