rule TTP_XOR_MULT_DOSStub_128d {
  strings:
    $key_128d = { 46 e5 [2] 32 fd [2] 75 ff [2] 32 ee [2] 7c e2 [2] 70 e8 [2] 67 e3 [2] 7c ad [2] 41 }

  condition:
    any of them
}