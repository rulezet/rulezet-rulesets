rule TTP_XOR_MULT_DOSStub_41df {
  strings:
    $key_41df = { 15 b7 [2] 61 af [2] 26 ad [2] 61 bc [2] 2f b0 [2] 23 ba [2] 34 b1 [2] 2f ff [2] 12 }

  condition:
    any of them
}