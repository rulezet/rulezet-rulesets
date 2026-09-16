rule TTP_XOR_MULT_DOSStub_8a50 {
  strings:
    $key_8a50 = { de 38 [2] aa 20 [2] ed 22 [2] aa 33 [2] e4 3f [2] e8 35 [2] ff 3e [2] e4 70 [2] d9 }

  condition:
    any of them
}