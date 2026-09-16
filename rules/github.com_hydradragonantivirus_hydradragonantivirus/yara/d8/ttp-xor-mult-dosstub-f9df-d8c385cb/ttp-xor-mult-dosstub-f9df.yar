rule TTP_XOR_MULT_DOSStub_f9df {
  strings:
    $key_f9df = { ad b7 [2] d9 af [2] 9e ad [2] d9 bc [2] 97 b0 [2] 9b ba [2] 8c b1 [2] 97 ff [2] aa }

  condition:
    any of them
}