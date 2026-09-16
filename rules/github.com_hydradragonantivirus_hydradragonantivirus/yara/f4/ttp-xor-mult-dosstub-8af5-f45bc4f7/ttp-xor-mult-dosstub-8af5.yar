rule TTP_XOR_MULT_DOSStub_8af5 {
  strings:
    $key_8af5 = { de 9d [2] aa 85 [2] ed 87 [2] aa 96 [2] e4 9a [2] e8 90 [2] ff 9b [2] e4 d5 [2] d9 }

  condition:
    any of them
}