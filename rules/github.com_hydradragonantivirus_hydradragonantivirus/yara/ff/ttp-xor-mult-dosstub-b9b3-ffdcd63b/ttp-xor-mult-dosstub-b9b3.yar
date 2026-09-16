rule TTP_XOR_MULT_DOSStub_b9b3 {
  strings:
    $key_b9b3 = { ed db [2] 99 c3 [2] de c1 [2] 99 d0 [2] d7 dc [2] db d6 [2] cc dd [2] d7 93 [2] ea }

  condition:
    any of them
}