rule TTP_XOR_MULT_DOSStub_5d8d {
  strings:
    $key_5d8d = { 09 e5 [2] 7d fd [2] 3a ff [2] 7d ee [2] 33 e2 [2] 3f e8 [2] 28 e3 [2] 33 ad [2] 0e }

  condition:
    any of them
}