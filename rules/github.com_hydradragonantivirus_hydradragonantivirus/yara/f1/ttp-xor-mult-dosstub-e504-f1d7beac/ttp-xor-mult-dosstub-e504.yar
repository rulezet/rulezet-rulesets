rule TTP_XOR_MULT_DOSStub_e504 {
  strings:
    $key_e504 = { b1 6c [2] c5 74 [2] 82 76 [2] c5 67 [2] 8b 6b [2] 87 61 [2] 90 6a [2] 8b 24 [2] b6 }

  condition:
    any of them
}