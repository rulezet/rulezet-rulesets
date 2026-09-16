rule TTP_XOR_MULT_DOSStub_56bc {
  strings:
    $key_56bc = { 02 d4 [2] 76 cc [2] 31 ce [2] 76 df [2] 38 d3 [2] 34 d9 [2] 23 d2 [2] 38 9c [2] 05 }

  condition:
    any of them
}