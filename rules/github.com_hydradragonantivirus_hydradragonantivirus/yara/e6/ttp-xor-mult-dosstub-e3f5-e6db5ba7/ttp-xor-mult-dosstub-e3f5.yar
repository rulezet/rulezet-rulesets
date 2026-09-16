rule TTP_XOR_MULT_DOSStub_e3f5 {
  strings:
    $key_e3f5 = { b7 9d [2] c3 85 [2] 84 87 [2] c3 96 [2] 8d 9a [2] 81 90 [2] 96 9b [2] 8d d5 [2] b0 }

  condition:
    any of them
}