rule TTP_XOR_MULT_DOSStub_11bc {
  strings:
    $key_11bc = { 45 d4 [2] 31 cc [2] 76 ce [2] 31 df [2] 7f d3 [2] 73 d9 [2] 64 d2 [2] 7f 9c [2] 42 }

  condition:
    any of them
}