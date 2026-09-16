rule TTP_XOR_MULT_DOSStub_e5bc {
  strings:
    $key_e5bc = { b1 d4 [2] c5 cc [2] 82 ce [2] c5 df [2] 8b d3 [2] 87 d9 [2] 90 d2 [2] 8b 9c [2] b6 }

  condition:
    any of them
}