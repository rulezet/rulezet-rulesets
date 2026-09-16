rule TTP_XOR_MULT_DOSStub_feec {
  strings:
    $key_feec = { aa 84 [2] de 9c [2] 99 9e [2] de 8f [2] 90 83 [2] 9c 89 [2] 8b 82 [2] 90 cc [2] ad }

  condition:
    any of them
}