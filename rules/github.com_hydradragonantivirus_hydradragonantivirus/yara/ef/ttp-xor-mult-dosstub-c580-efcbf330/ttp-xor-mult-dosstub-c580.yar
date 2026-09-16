rule TTP_XOR_MULT_DOSStub_c580 {
  strings:
    $key_c580 = { 91 e8 [2] e5 f0 [2] a2 f2 [2] e5 e3 [2] ab ef [2] a7 e5 [2] b0 ee [2] ab a0 [2] 96 }

  condition:
    any of them
}