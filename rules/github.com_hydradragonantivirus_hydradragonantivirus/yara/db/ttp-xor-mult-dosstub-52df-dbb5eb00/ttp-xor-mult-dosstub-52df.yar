rule TTP_XOR_MULT_DOSStub_52df {
  strings:
    $key_52df = { 06 b7 [2] 72 af [2] 35 ad [2] 72 bc [2] 3c b0 [2] 30 ba [2] 27 b1 [2] 3c ff [2] 01 }

  condition:
    any of them
}