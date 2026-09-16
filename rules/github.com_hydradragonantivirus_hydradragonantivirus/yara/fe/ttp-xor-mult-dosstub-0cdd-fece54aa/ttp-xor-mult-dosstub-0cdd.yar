rule TTP_XOR_MULT_DOSStub_0cdd {
  strings:
    $key_0cdd = { 58 b5 [2] 2c ad [2] 6b af [2] 2c be [2] 62 b2 [2] 6e b8 [2] 79 b3 [2] 62 fd [2] 5f }

  condition:
    any of them
}