rule TTP_XOR_MULT_DOSStub_73b5 {
  strings:
    $key_73b5 = { 27 dd [2] 53 c5 [2] 14 c7 [2] 53 d6 [2] 1d da [2] 11 d0 [2] 06 db [2] 1d 95 [2] 20 }

  condition:
    any of them
}