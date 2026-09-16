rule TTP_XOR_MULT_DOSStub_b062 {
  strings:
    $key_b062 = { e4 0a [2] 90 12 [2] d7 10 [2] 90 01 [2] de 0d [2] d2 07 [2] c5 0c [2] de 42 [2] e3 }

  condition:
    any of them
}