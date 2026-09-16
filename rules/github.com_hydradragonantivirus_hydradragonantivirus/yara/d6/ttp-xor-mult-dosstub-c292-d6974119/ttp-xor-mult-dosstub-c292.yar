rule TTP_XOR_MULT_DOSStub_c292 {
  strings:
    $key_c292 = { 96 fa [2] e2 e2 [2] a5 e0 [2] e2 f1 [2] ac fd [2] a0 f7 [2] b7 fc [2] ac b2 [2] 91 }

  condition:
    any of them
}