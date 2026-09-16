rule TTP_XOR_MULT_DOSStub_8a7a {
  strings:
    $key_8a7a = { de 12 [2] aa 0a [2] ed 08 [2] aa 19 [2] e4 15 [2] e8 1f [2] ff 14 [2] e4 5a [2] d9 }

  condition:
    any of them
}