rule TTP_XOR_MULT_DOSStub_57b3 {
  strings:
    $key_57b3 = { 03 db [2] 77 c3 [2] 30 c1 [2] 77 d0 [2] 39 dc [2] 35 d6 [2] 22 dd [2] 39 93 [2] 04 }

  condition:
    any of them
}