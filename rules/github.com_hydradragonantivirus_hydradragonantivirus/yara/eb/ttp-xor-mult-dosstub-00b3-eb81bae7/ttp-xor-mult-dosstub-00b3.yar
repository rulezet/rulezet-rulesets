rule TTP_XOR_MULT_DOSStub_00b3 {
  strings:
    $key_00b3 = { 54 db [2] 20 c3 [2] 67 c1 [2] 20 d0 [2] 6e dc [2] 62 d6 [2] 75 dd [2] 6e 93 [2] 53 }

  condition:
    any of them
}