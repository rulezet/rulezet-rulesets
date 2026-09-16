rule TTP_XOR_MULT_DOSStub_dbce {
  strings:
    $key_dbce = { 8f a6 [2] fb be [2] bc bc [2] fb ad [2] b5 a1 [2] b9 ab [2] ae a0 [2] b5 ee [2] 88 }

  condition:
    any of them
}