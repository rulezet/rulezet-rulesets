rule TTP_XOR_MULT_DOSStub_24bc {
  strings:
    $key_24bc = { 70 d4 [2] 04 cc [2] 43 ce [2] 04 df [2] 4a d3 [2] 46 d9 [2] 51 d2 [2] 4a 9c [2] 77 }

  condition:
    any of them
}