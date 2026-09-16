rule TTP_XOR_MULT_DOSStub_d5df {
  strings:
    $key_d5df = { 81 b7 [2] f5 af [2] b2 ad [2] f5 bc [2] bb b0 [2] b7 ba [2] a0 b1 [2] bb ff [2] 86 }

  condition:
    any of them
}