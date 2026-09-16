rule TTP_XOR_MULT_DOSStub_748f {
  strings:
    $key_748f = { 20 e7 [2] 54 ff [2] 13 fd [2] 54 ec [2] 1a e0 [2] 16 ea [2] 01 e1 [2] 1a af [2] 27 }

  condition:
    any of them
}