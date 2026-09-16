rule TTP_XOR_MULT_DOSStub_8a3f {
  strings:
    $key_8a3f = { de 57 [2] aa 4f [2] ed 4d [2] aa 5c [2] e4 50 [2] e8 5a [2] ff 51 [2] e4 1f [2] d9 }

  condition:
    any of them
}