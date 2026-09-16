rule TTP_XOR_MULT_DOSStub_8b9c {
  strings:
    $key_8b9c = { df f4 [2] ab ec [2] ec ee [2] ab ff [2] e5 f3 [2] e9 f9 [2] fe f2 [2] e5 bc [2] d8 }

  condition:
    any of them
}