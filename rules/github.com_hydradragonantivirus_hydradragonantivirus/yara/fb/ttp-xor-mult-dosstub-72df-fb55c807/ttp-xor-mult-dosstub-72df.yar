rule TTP_XOR_MULT_DOSStub_72df {
  strings:
    $key_72df = { 26 b7 [2] 52 af [2] 15 ad [2] 52 bc [2] 1c b0 [2] 10 ba [2] 07 b1 [2] 1c ff [2] 21 }

  condition:
    any of them
}