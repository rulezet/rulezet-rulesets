rule TTP_XOR_MULT_DOSStub_50b5 {
  strings:
    $key_50b5 = { 04 dd [2] 70 c5 [2] 37 c7 [2] 70 d6 [2] 3e da [2] 32 d0 [2] 25 db [2] 3e 95 [2] 03 }

  condition:
    any of them
}