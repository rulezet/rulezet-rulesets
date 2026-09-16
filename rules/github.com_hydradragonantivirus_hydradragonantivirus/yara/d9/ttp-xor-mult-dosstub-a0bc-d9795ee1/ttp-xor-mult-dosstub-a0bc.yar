rule TTP_XOR_MULT_DOSStub_a0bc {
  strings:
    $key_a0bc = { f4 d4 [2] 80 cc [2] c7 ce [2] 80 df [2] ce d3 [2] c2 d9 [2] d5 d2 [2] ce 9c [2] f3 }

  condition:
    any of them
}