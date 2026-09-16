rule TTP_XOR_MULT_DOSStub_e063 {
  strings:
    $key_e063 = { b4 0b [2] c0 13 [2] 87 11 [2] c0 00 [2] 8e 0c [2] 82 06 [2] 95 0d [2] 8e 43 [2] b3 }

  condition:
    any of them
}