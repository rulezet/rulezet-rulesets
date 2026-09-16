rule TTP_XOR_MULT_DOSStub_47bc {
  strings:
    $key_47bc = { 13 d4 [2] 67 cc [2] 20 ce [2] 67 df [2] 29 d3 [2] 25 d9 [2] 32 d2 [2] 29 9c [2] 14 }

  condition:
    any of them
}