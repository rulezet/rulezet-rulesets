rule TTP_XOR_MULT_DOSStub_0dce {
  strings:
    $key_0dce = { 59 a6 [2] 2d be [2] 6a bc [2] 2d ad [2] 63 a1 [2] 6f ab [2] 78 a0 [2] 63 ee [2] 5e }

  condition:
    any of them
}