rule TTP_XOR_MULT_DOSStub_32bc {
  strings:
    $key_32bc = { 66 d4 [2] 12 cc [2] 55 ce [2] 12 df [2] 5c d3 [2] 50 d9 [2] 47 d2 [2] 5c 9c [2] 61 }

  condition:
    any of them
}