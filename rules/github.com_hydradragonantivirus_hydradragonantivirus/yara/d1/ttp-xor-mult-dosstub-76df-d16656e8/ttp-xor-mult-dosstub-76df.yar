rule TTP_XOR_MULT_DOSStub_76df {
  strings:
    $key_76df = { 22 b7 [2] 56 af [2] 11 ad [2] 56 bc [2] 18 b0 [2] 14 ba [2] 03 b1 [2] 18 ff [2] 25 }

  condition:
    any of them
}