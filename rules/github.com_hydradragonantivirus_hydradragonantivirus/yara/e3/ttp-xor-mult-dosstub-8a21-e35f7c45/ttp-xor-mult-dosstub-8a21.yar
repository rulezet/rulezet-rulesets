rule TTP_XOR_MULT_DOSStub_8a21 {
  strings:
    $key_8a21 = { de 49 [2] aa 51 [2] ed 53 [2] aa 42 [2] e4 4e [2] e8 44 [2] ff 4f [2] e4 01 [2] d9 }

  condition:
    any of them
}