rule TTP_XOR_MULT_DOSStub_f7b8 {
  strings:
    $key_f7b8 = { a3 d0 [2] d7 c8 [2] 90 ca [2] d7 db [2] 99 d7 [2] 95 dd [2] 82 d6 [2] 99 98 [2] a4 }

  condition:
    any of them
}