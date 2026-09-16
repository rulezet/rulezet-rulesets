rule TTP_XOR_MULT_DOSStub_8a26 {
  strings:
    $key_8a26 = { de 4e [2] aa 56 [2] ed 54 [2] aa 45 [2] e4 49 [2] e8 43 [2] ff 48 [2] e4 06 [2] d9 }

  condition:
    any of them
}