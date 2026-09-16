rule TTP_XOR_MULT_DOSStub_04bc {
  strings:
    $key_04bc = { 50 d4 [2] 24 cc [2] 63 ce [2] 24 df [2] 6a d3 [2] 66 d9 [2] 71 d2 [2] 6a 9c [2] 57 }

  condition:
    any of them
}