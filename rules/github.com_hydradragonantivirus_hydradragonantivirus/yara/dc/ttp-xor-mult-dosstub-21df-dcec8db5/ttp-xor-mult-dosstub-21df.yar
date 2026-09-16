rule TTP_XOR_MULT_DOSStub_21df {
  strings:
    $key_21df = { 75 b7 [2] 01 af [2] 46 ad [2] 01 bc [2] 4f b0 [2] 43 ba [2] 54 b1 [2] 4f ff [2] 72 }

  condition:
    any of them
}