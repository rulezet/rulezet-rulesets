rule TTP_XOR_MULT_DOSStub_e5e9 {
  strings:
    $key_e5e9 = { b1 81 [2] c5 99 [2] 82 9b [2] c5 8a [2] 8b 86 [2] 87 8c [2] 90 87 [2] 8b c9 [2] b6 }

  condition:
    any of them
}