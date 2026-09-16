rule TTP_XOR_MULT_DOSStub_0ab3 {
  strings:
    $key_0ab3 = { 5e db [2] 2a c3 [2] 6d c1 [2] 2a d0 [2] 64 dc [2] 68 d6 [2] 7f dd [2] 64 93 [2] 59 }

  condition:
    any of them
}