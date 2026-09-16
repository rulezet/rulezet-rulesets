rule TTP_XOR_MULT_DOSStub_dff5 {
  strings:
    $key_dff5 = { 8b 9d [2] ff 85 [2] b8 87 [2] ff 96 [2] b1 9a [2] bd 90 [2] aa 9b [2] b1 d5 [2] 8c }

  condition:
    any of them
}