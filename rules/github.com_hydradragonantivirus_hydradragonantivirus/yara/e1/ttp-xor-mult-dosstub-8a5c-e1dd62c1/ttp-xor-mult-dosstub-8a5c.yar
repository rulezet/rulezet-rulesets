rule TTP_XOR_MULT_DOSStub_8a5c {
  strings:
    $key_8a5c = { de 34 [2] aa 2c [2] ed 2e [2] aa 3f [2] e4 33 [2] e8 39 [2] ff 32 [2] e4 7c [2] d9 }

  condition:
    any of them
}