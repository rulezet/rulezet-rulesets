rule TTP_XOR_MULT_DOSStub_e004 {
  strings:
    $key_e004 = { b4 6c [2] c0 74 [2] 87 76 [2] c0 67 [2] 8e 6b [2] 82 61 [2] 95 6a [2] 8e 24 [2] b3 }

  condition:
    any of them
}