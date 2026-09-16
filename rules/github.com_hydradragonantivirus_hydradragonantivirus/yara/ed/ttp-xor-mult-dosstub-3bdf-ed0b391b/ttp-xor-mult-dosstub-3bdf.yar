rule TTP_XOR_MULT_DOSStub_3bdf {
  strings:
    $key_3bdf = { 6f b7 [2] 1b af [2] 5c ad [2] 1b bc [2] 55 b0 [2] 59 ba [2] 4e b1 [2] 55 ff [2] 68 }

  condition:
    any of them
}