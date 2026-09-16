rule TTP_XOR_MULT_DOSStub_e9df {
  strings:
    $key_e9df = { bd b7 [2] c9 af [2] 8e ad [2] c9 bc [2] 87 b0 [2] 8b ba [2] 9c b1 [2] 87 ff [2] ba }

  condition:
    any of them
}