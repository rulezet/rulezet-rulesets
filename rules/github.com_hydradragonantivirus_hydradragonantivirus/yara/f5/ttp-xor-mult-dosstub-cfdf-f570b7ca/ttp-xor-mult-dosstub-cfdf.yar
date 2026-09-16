rule TTP_XOR_MULT_DOSStub_cfdf {
  strings:
    $key_cfdf = { 9b b7 [2] ef af [2] a8 ad [2] ef bc [2] a1 b0 [2] ad ba [2] ba b1 [2] a1 ff [2] 9c }

  condition:
    any of them
}