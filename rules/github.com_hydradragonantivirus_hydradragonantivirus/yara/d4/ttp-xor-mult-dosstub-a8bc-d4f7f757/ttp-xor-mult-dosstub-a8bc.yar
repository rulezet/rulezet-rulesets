rule TTP_XOR_MULT_DOSStub_a8bc {
  strings:
    $key_a8bc = { fc d4 [2] 88 cc [2] cf ce [2] 88 df [2] c6 d3 [2] ca d9 [2] dd d2 [2] c6 9c [2] fb }

  condition:
    any of them
}