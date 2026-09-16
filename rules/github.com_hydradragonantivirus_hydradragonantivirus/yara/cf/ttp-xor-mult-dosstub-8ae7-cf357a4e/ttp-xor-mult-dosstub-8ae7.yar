rule TTP_XOR_MULT_DOSStub_8ae7 {
  strings:
    $key_8ae7 = { de 8f [2] aa 97 [2] ed 95 [2] aa 84 [2] e4 88 [2] e8 82 [2] ff 89 [2] e4 c7 [2] d9 }

  condition:
    any of them
}