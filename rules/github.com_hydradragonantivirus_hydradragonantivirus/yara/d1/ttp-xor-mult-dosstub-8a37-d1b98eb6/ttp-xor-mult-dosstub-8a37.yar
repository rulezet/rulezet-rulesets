rule TTP_XOR_MULT_DOSStub_8a37 {
  strings:
    $key_8a37 = { de 5f [2] aa 47 [2] ed 45 [2] aa 54 [2] e4 58 [2] e8 52 [2] ff 59 [2] e4 17 [2] d9 }

  condition:
    any of them
}