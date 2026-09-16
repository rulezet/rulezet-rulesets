rule TTP_XOR_MULT_DOSStub_7cce {
  strings:
    $key_7cce = { 28 a6 [2] 5c be [2] 1b bc [2] 5c ad [2] 12 a1 [2] 1e ab [2] 09 a0 [2] 12 ee [2] 2f }

  condition:
    any of them
}