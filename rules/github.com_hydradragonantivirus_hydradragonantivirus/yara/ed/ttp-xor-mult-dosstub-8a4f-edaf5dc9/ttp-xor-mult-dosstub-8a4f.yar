rule TTP_XOR_MULT_DOSStub_8a4f {
  strings:
    $key_8a4f = { de 27 [2] aa 3f [2] ed 3d [2] aa 2c [2] e4 20 [2] e8 2a [2] ff 21 [2] e4 6f [2] d9 }

  condition:
    any of them
}