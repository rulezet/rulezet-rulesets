rule TTP_XOR_MULT_DOSStub_8a5f {
  strings:
    $key_8a5f = { de 37 [2] aa 2f [2] ed 2d [2] aa 3c [2] e4 30 [2] e8 3a [2] ff 31 [2] e4 7f [2] d9 }

  condition:
    any of them
}