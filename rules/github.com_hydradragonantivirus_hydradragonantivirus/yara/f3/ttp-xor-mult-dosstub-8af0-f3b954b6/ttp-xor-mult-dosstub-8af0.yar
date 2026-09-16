rule TTP_XOR_MULT_DOSStub_8af0 {
  strings:
    $key_8af0 = { de 98 [2] aa 80 [2] ed 82 [2] aa 93 [2] e4 9f [2] e8 95 [2] ff 9e [2] e4 d0 [2] d9 }

  condition:
    any of them
}