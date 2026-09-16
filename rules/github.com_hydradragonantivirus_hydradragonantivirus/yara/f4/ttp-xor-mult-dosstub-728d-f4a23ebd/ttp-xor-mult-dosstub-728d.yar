rule TTP_XOR_MULT_DOSStub_728d {
  strings:
    $key_728d = { 26 e5 [2] 52 fd [2] 15 ff [2] 52 ee [2] 1c e2 [2] 10 e8 [2] 07 e3 [2] 1c ad [2] 21 }

  condition:
    any of them
}