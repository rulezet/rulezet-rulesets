rule TTP_XOR_MULT_DOSStub_8a07 {
  strings:
    $key_8a07 = { de 6f [2] aa 77 [2] ed 75 [2] aa 64 [2] e4 68 [2] e8 62 [2] ff 69 [2] e4 27 [2] d9 }

  condition:
    any of them
}