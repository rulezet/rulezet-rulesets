rule TTP_XOR_MULT_DOSStub_8ae5 {
  strings:
    $key_8ae5 = { de 8d [2] aa 95 [2] ed 97 [2] aa 86 [2] e4 8a [2] e8 80 [2] ff 8b [2] e4 c5 [2] d9 }

  condition:
    any of them
}