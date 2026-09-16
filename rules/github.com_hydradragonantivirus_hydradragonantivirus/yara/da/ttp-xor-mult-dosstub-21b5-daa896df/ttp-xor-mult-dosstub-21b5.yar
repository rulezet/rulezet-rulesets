rule TTP_XOR_MULT_DOSStub_21b5 {
  strings:
    $key_21b5 = { 75 dd [2] 01 c5 [2] 46 c7 [2] 01 d6 [2] 4f da [2] 43 d0 [2] 54 db [2] 4f 95 [2] 72 }

  condition:
    any of them
}