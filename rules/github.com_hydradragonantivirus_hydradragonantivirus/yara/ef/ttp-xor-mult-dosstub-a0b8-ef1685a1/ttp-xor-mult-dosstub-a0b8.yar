rule TTP_XOR_MULT_DOSStub_a0b8 {
  strings:
    $key_a0b8 = { f4 d0 [2] 80 c8 [2] c7 ca [2] 80 db [2] ce d7 [2] c2 dd [2] d5 d6 [2] ce 98 [2] f3 }

  condition:
    any of them
}