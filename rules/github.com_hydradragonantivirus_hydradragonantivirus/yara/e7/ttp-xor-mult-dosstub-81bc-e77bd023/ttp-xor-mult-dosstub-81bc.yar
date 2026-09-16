rule TTP_XOR_MULT_DOSStub_81bc {
  strings:
    $key_81bc = { d5 d4 [2] a1 cc [2] e6 ce [2] a1 df [2] ef d3 [2] e3 d9 [2] f4 d2 [2] ef 9c [2] d2 }

  condition:
    any of them
}