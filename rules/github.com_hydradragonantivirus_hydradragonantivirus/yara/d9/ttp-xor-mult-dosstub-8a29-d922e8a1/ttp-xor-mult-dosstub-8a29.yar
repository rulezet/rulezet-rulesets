rule TTP_XOR_MULT_DOSStub_8a29 {
  strings:
    $key_8a29 = { de 41 [2] aa 59 [2] ed 5b [2] aa 4a [2] e4 46 [2] e8 4c [2] ff 47 [2] e4 09 [2] d9 }

  condition:
    any of them
}