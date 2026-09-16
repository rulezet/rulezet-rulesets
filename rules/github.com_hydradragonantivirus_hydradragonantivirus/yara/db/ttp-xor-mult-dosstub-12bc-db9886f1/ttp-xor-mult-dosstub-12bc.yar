rule TTP_XOR_MULT_DOSStub_12bc {
  strings:
    $key_12bc = { 46 d4 [2] 32 cc [2] 75 ce [2] 32 df [2] 7c d3 [2] 70 d9 [2] 67 d2 [2] 7c 9c [2] 41 }

  condition:
    any of them
}