rule TTP_XOR_MULT_DOSStub_8af3 {
  strings:
    $key_8af3 = { de 9b [2] aa 83 [2] ed 81 [2] aa 90 [2] e4 9c [2] e8 96 [2] ff 9d [2] e4 d3 [2] d9 }

  condition:
    any of them
}