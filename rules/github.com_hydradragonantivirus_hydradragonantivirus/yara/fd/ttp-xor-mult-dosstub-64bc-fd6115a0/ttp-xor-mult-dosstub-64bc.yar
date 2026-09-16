rule TTP_XOR_MULT_DOSStub_64bc {
  strings:
    $key_64bc = { 30 d4 [2] 44 cc [2] 03 ce [2] 44 df [2] 0a d3 [2] 06 d9 [2] 11 d2 [2] 0a 9c [2] 37 }

  condition:
    any of them
}