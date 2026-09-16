rule TTP_XOR_MULT_DOSStub_b7bc {
  strings:
    $key_b7bc = { e3 d4 [2] 97 cc [2] d0 ce [2] 97 df [2] d9 d3 [2] d5 d9 [2] c2 d2 [2] d9 9c [2] e4 }

  condition:
    any of them
}