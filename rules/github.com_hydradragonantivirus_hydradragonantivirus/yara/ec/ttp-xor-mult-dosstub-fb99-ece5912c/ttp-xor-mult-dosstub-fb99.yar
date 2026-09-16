rule TTP_XOR_MULT_DOSStub_fb99 {
  strings:
    $key_fb99 = { af f1 [2] db e9 [2] 9c eb [2] db fa [2] 95 f6 [2] 99 fc [2] 8e f7 [2] 95 b9 [2] a8 }

  condition:
    any of them
}