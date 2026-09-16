rule TTP_XOR_MULT_DOSStub_2cce {
  strings:
    $key_2cce = { 78 a6 [2] 0c be [2] 4b bc [2] 0c ad [2] 42 a1 [2] 4e ab [2] 59 a0 [2] 42 ee [2] 7f }

  condition:
    any of them
}