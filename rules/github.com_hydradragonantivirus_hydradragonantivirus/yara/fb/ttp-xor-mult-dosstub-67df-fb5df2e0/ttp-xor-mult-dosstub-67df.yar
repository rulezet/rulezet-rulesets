rule TTP_XOR_MULT_DOSStub_67df {
  strings:
    $key_67df = { 33 b7 [2] 47 af [2] 00 ad [2] 47 bc [2] 09 b0 [2] 05 ba [2] 12 b1 [2] 09 ff [2] 34 }

  condition:
    any of them
}