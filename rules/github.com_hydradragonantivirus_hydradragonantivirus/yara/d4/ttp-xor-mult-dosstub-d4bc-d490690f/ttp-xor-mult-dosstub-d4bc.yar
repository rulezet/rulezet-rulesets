rule TTP_XOR_MULT_DOSStub_d4bc {
  strings:
    $key_d4bc = { 80 d4 [2] f4 cc [2] b3 ce [2] f4 df [2] ba d3 [2] b6 d9 [2] a1 d2 [2] ba 9c [2] 87 }

  condition:
    any of them
}