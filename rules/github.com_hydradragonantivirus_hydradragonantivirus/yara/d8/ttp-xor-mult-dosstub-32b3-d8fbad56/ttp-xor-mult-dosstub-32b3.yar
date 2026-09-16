rule TTP_XOR_MULT_DOSStub_32b3 {
  strings:
    $key_32b3 = { 66 db [2] 12 c3 [2] 55 c1 [2] 12 d0 [2] 5c dc [2] 50 d6 [2] 47 dd [2] 5c 93 [2] 61 }

  condition:
    any of them
}