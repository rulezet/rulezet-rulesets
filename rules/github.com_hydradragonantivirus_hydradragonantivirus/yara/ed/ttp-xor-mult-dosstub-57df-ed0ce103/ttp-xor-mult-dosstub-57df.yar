rule TTP_XOR_MULT_DOSStub_57df {
  strings:
    $key_57df = { 03 b7 [2] 77 af [2] 30 ad [2] 77 bc [2] 39 b0 [2] 35 ba [2] 22 b1 [2] 39 ff [2] 04 }

  condition:
    any of them
}