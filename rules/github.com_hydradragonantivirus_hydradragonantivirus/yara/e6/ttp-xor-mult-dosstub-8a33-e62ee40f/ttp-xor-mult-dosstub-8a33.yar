rule TTP_XOR_MULT_DOSStub_8a33 {
  strings:
    $key_8a33 = { de 5b [2] aa 43 [2] ed 41 [2] aa 50 [2] e4 5c [2] e8 56 [2] ff 5d [2] e4 13 [2] d9 }

  condition:
    any of them
}