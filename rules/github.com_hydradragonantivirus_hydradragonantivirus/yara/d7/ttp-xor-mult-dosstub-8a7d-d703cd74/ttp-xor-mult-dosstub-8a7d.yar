rule TTP_XOR_MULT_DOSStub_8a7d {
  strings:
    $key_8a7d = { de 15 [2] aa 0d [2] ed 0f [2] aa 1e [2] e4 12 [2] e8 18 [2] ff 13 [2] e4 5d [2] d9 }

  condition:
    any of them
}