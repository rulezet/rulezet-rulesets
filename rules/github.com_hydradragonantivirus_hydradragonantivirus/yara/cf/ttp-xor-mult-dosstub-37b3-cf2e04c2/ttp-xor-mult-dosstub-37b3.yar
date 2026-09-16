rule TTP_XOR_MULT_DOSStub_37b3 {
  strings:
    $key_37b3 = { 63 db [2] 17 c3 [2] 50 c1 [2] 17 d0 [2] 59 dc [2] 55 d6 [2] 42 dd [2] 59 93 [2] 64 }

  condition:
    any of them
}