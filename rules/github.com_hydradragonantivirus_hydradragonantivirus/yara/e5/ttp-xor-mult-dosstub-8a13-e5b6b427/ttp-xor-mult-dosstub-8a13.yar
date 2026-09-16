rule TTP_XOR_MULT_DOSStub_8a13 {
  strings:
    $key_8a13 = { de 7b [2] aa 63 [2] ed 61 [2] aa 70 [2] e4 7c [2] e8 76 [2] ff 7d [2] e4 33 [2] d9 }

  condition:
    any of them
}