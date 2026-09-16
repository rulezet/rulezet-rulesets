rule TTP_XOR_MULT_DOSStub_dff1 {
  strings:
    $key_dff1 = { 8b 99 [2] ff 81 [2] b8 83 [2] ff 92 [2] b1 9e [2] bd 94 [2] aa 9f [2] b1 d1 [2] 8c }

  condition:
    any of them
}