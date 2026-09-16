rule TTP_XOR_MULT_DOSStub_6cce {
  strings:
    $key_6cce = { 38 a6 [2] 4c be [2] 0b bc [2] 4c ad [2] 02 a1 [2] 0e ab [2] 19 a0 [2] 02 ee [2] 3f }

  condition:
    any of them
}