rule TTP_XOR_MULT_DOSStub_8a31 {
  strings:
    $key_8a31 = { de 59 [2] aa 41 [2] ed 43 [2] aa 52 [2] e4 5e [2] e8 54 [2] ff 5f [2] e4 11 [2] d9 }

  condition:
    any of them
}