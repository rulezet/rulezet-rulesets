rule TTP_XOR_MULT_DOSStub_07b5 {
  strings:
    $key_07b5 = { 53 dd [2] 27 c5 [2] 60 c7 [2] 27 d6 [2] 69 da [2] 65 d0 [2] 72 db [2] 69 95 [2] 54 }

  condition:
    any of them
}