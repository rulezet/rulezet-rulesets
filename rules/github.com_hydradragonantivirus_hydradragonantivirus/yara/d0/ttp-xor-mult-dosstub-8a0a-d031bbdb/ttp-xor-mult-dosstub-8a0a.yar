rule TTP_XOR_MULT_DOSStub_8a0a {
  strings:
    $key_8a0a = { de 62 [2] aa 7a [2] ed 78 [2] aa 69 [2] e4 65 [2] e8 6f [2] ff 64 [2] e4 2a [2] d9 }

  condition:
    any of them
}