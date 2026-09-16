rule TTP_XOR_MULT_DOSStub_11df {
  strings:
    $key_11df = { 45 b7 [2] 31 af [2] 76 ad [2] 31 bc [2] 7f b0 [2] 73 ba [2] 64 b1 [2] 7f ff [2] 42 }

  condition:
    any of them
}