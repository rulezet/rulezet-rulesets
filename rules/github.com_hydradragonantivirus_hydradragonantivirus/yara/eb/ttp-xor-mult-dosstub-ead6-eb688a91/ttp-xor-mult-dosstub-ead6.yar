rule TTP_XOR_MULT_DOSStub_ead6 {
  strings:
    $key_ead6 = { be be [2] ca a6 [2] 8d a4 [2] ca b5 [2] 84 b9 [2] 88 b3 [2] 9f b8 [2] 84 f6 [2] b9 }

  condition:
    any of them
}