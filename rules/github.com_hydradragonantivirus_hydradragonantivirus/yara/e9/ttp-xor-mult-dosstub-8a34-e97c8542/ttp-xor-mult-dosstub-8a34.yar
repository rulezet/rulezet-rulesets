rule TTP_XOR_MULT_DOSStub_8a34 {
  strings:
    $key_8a34 = { de 5c [2] aa 44 [2] ed 46 [2] aa 57 [2] e4 5b [2] e8 51 [2] ff 5a [2] e4 14 [2] d9 }

  condition:
    any of them
}