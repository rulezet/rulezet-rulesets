rule TTP_XOR_MULT_DOSStub_89bc {
  strings:
    $key_89bc = { dd d4 [2] a9 cc [2] ee ce [2] a9 df [2] e7 d3 [2] eb d9 [2] fc d2 [2] e7 9c [2] da }

  condition:
    any of them
}