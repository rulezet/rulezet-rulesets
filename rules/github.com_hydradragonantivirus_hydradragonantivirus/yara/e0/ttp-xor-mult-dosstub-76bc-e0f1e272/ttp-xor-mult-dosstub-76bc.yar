rule TTP_XOR_MULT_DOSStub_76bc {
  strings:
    $key_76bc = { 22 d4 [2] 56 cc [2] 11 ce [2] 56 df [2] 18 d3 [2] 14 d9 [2] 03 d2 [2] 18 9c [2] 25 }

  condition:
    any of them
}