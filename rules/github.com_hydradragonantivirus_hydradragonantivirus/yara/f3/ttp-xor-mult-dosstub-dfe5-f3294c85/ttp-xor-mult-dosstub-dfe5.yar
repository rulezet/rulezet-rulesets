rule TTP_XOR_MULT_DOSStub_dfe5 {
  strings:
    $key_dfe5 = { 8b 8d [2] ff 95 [2] b8 97 [2] ff 86 [2] b1 8a [2] bd 80 [2] aa 8b [2] b1 c5 [2] 8c }

  condition:
    any of them
}