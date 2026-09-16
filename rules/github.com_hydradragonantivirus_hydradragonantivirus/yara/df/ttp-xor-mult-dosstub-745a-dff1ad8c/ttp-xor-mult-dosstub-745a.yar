rule TTP_XOR_MULT_DOSStub_745a {
  strings:
    $key_745a = { 20 32 [2] 54 2a [2] 13 28 [2] 54 39 [2] 1a 35 [2] 16 3f [2] 01 34 [2] 1a 7a [2] 27 }

  condition:
    any of them
}