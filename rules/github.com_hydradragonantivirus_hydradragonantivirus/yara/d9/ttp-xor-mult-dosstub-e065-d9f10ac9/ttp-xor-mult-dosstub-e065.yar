rule TTP_XOR_MULT_DOSStub_e065 {
  strings:
    $key_e065 = { b4 0d [2] c0 15 [2] 87 17 [2] c0 06 [2] 8e 0a [2] 82 00 [2] 95 0b [2] 8e 45 [2] b3 }

  condition:
    any of them
}