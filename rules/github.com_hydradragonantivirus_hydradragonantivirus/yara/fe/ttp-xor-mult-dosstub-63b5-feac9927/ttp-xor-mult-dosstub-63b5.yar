rule TTP_XOR_MULT_DOSStub_63b5 {
  strings:
    $key_63b5 = { 37 dd [2] 43 c5 [2] 04 c7 [2] 43 d6 [2] 0d da [2] 01 d0 [2] 16 db [2] 0d 95 [2] 30 }

  condition:
    any of them
}