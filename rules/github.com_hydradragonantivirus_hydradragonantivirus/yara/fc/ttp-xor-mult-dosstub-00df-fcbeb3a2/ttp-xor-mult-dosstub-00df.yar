rule TTP_XOR_MULT_DOSStub_00df {
  strings:
    $key_00df = { 54 b7 [2] 20 af [2] 67 ad [2] 20 bc [2] 6e b0 [2] 62 ba [2] 75 b1 [2] 6e ff [2] 53 }

  condition:
    any of them
}