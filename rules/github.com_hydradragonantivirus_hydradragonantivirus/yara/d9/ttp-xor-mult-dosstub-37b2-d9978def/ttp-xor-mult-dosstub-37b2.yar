rule TTP_XOR_MULT_DOSStub_37b2 {
  strings:
    $key_37b2 = { 63 da [2] 17 c2 [2] 50 c0 [2] 17 d1 [2] 59 dd [2] 55 d7 [2] 42 dc [2] 59 92 [2] 64 }

  condition:
    any of them
}