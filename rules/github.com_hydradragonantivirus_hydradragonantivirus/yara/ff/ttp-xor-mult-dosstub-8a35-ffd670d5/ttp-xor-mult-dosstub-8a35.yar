rule TTP_XOR_MULT_DOSStub_8a35 {
  strings:
    $key_8a35 = { de 5d [2] aa 45 [2] ed 47 [2] aa 56 [2] e4 5a [2] e8 50 [2] ff 5b [2] e4 15 [2] d9 }

  condition:
    any of them
}