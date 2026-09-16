rule TTP_XOR_MULT_DOSStub_c599 {
  strings:
    $key_c599 = { 91 f1 [2] e5 e9 [2] a2 eb [2] e5 fa [2] ab f6 [2] a7 fc [2] b0 f7 [2] ab b9 [2] 96 }

  condition:
    any of them
}