rule TTP_XOR_MULT_DOSStub_33bc {
  strings:
    $key_33bc = { 67 d4 [2] 13 cc [2] 54 ce [2] 13 df [2] 5d d3 [2] 51 d9 [2] 46 d2 [2] 5d 9c [2] 60 }

  condition:
    any of them
}