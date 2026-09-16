rule TTP_XOR_MULT_DOSStub_60df {
  strings:
    $key_60df = { 34 b7 [2] 40 af [2] 07 ad [2] 40 bc [2] 0e b0 [2] 02 ba [2] 15 b1 [2] 0e ff [2] 33 }

  condition:
    any of them
}