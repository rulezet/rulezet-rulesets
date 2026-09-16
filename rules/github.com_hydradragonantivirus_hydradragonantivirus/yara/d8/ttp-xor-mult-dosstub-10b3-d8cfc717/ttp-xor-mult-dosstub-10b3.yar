rule TTP_XOR_MULT_DOSStub_10b3 {
  strings:
    $key_10b3 = { 44 db [2] 30 c3 [2] 77 c1 [2] 30 d0 [2] 7e dc [2] 72 d6 [2] 65 dd [2] 7e 93 [2] 43 }

  condition:
    any of them
}