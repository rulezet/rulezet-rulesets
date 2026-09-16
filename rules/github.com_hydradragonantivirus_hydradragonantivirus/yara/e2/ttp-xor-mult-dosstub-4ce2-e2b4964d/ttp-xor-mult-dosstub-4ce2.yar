rule TTP_XOR_MULT_DOSStub_4ce2 {
  strings:
    $key_4ce2 = { 18 8a [2] 6c 92 [2] 2b 90 [2] 6c 81 [2] 22 8d [2] 2e 87 [2] 39 8c [2] 22 c2 [2] 1f }

  condition:
    any of them
}