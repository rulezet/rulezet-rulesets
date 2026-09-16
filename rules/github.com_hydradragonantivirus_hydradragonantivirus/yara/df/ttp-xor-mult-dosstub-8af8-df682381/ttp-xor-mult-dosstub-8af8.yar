rule TTP_XOR_MULT_DOSStub_8af8 {
  strings:
    $key_8af8 = { de 90 [2] aa 88 [2] ed 8a [2] aa 9b [2] e4 97 [2] e8 9d [2] ff 96 [2] e4 d8 [2] d9 }

  condition:
    any of them
}