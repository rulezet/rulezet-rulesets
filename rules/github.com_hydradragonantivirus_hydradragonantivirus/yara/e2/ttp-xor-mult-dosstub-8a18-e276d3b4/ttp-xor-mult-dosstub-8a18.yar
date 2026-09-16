rule TTP_XOR_MULT_DOSStub_8a18 {
  strings:
    $key_8a18 = { de 70 [2] aa 68 [2] ed 6a [2] aa 7b [2] e4 77 [2] e8 7d [2] ff 76 [2] e4 38 [2] d9 }

  condition:
    any of them
}