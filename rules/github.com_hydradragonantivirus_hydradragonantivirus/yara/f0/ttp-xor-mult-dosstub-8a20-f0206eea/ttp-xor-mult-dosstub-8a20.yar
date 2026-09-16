rule TTP_XOR_MULT_DOSStub_8a20 {
  strings:
    $key_8a20 = { de 48 [2] aa 50 [2] ed 52 [2] aa 43 [2] e4 4f [2] e8 45 [2] ff 4e [2] e4 00 [2] d9 }

  condition:
    any of them
}