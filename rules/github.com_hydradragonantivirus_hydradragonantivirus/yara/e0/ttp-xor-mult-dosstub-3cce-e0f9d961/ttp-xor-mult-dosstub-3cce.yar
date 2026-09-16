rule TTP_XOR_MULT_DOSStub_3cce {
  strings:
    $key_3cce = { 68 a6 [2] 1c be [2] 5b bc [2] 1c ad [2] 52 a1 [2] 5e ab [2] 49 a0 [2] 52 ee [2] 6f }

  condition:
    any of them
}