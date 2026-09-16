rule TTP_XOR_MULT_DOSStub_8a42 {
  strings:
    $key_8a42 = { de 2a [2] aa 32 [2] ed 30 [2] aa 21 [2] e4 2d [2] e8 27 [2] ff 2c [2] e4 62 [2] d9 }

  condition:
    any of them
}