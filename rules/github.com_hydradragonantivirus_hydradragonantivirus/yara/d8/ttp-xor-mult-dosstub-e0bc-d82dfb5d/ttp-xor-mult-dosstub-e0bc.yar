rule TTP_XOR_MULT_DOSStub_e0bc {
  strings:
    $key_e0bc = { b4 d4 [2] c0 cc [2] 87 ce [2] c0 df [2] 8e d3 [2] 82 d9 [2] 95 d2 [2] 8e 9c [2] b3 }

  condition:
    any of them
}