rule TTP_XOR_MULT_DOSStub_b4bc {
  strings:
    $key_b4bc = { e0 d4 [2] 94 cc [2] d3 ce [2] 94 df [2] da d3 [2] d6 d9 [2] c1 d2 [2] da 9c [2] e7 }

  condition:
    any of them
}