rule TTP_XOR_MULT_DOSStub_43bc {
  strings:
    $key_43bc = { 17 d4 [2] 63 cc [2] 24 ce [2] 63 df [2] 2d d3 [2] 21 d9 [2] 36 d2 [2] 2d 9c [2] 10 }

  condition:
    any of them
}