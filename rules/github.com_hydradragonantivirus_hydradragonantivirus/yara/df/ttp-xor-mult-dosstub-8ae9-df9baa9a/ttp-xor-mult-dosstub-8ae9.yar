rule TTP_XOR_MULT_DOSStub_8ae9 {
  strings:
    $key_8ae9 = { de 81 [2] aa 99 [2] ed 9b [2] aa 8a [2] e4 86 [2] e8 8c [2] ff 87 [2] e4 c9 [2] d9 }

  condition:
    any of them
}