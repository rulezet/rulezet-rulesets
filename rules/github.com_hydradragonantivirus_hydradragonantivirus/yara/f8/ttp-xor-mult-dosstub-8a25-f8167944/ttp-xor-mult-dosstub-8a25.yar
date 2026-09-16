rule TTP_XOR_MULT_DOSStub_8a25 {
  strings:
    $key_8a25 = { de 4d [2] aa 55 [2] ed 57 [2] aa 46 [2] e4 4a [2] e8 40 [2] ff 4b [2] e4 05 [2] d9 }

  condition:
    any of them
}