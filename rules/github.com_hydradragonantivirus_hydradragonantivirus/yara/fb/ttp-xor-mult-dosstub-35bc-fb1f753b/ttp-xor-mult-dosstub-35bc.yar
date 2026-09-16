rule TTP_XOR_MULT_DOSStub_35bc {
  strings:
    $key_35bc = { 61 d4 [2] 15 cc [2] 52 ce [2] 15 df [2] 5b d3 [2] 57 d9 [2] 40 d2 [2] 5b 9c [2] 66 }

  condition:
    any of them
}