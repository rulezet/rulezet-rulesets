rule TTP_XOR_MULT_DOSStub_e5f5 {
  strings:
    $key_e5f5 = { b1 9d [2] c5 85 [2] 82 87 [2] c5 96 [2] 8b 9a [2] 87 90 [2] 90 9b [2] 8b d5 [2] b6 }

  condition:
    any of them
}