rule TTP_XOR_MULT_DOSStub_5bdf {
  strings:
    $key_5bdf = { 0f b7 [2] 7b af [2] 3c ad [2] 7b bc [2] 35 b0 [2] 39 ba [2] 2e b1 [2] 35 ff [2] 08 }

  condition:
    any of them
}