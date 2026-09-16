rule TTP_XOR_MULT_DOSStub_f0b3 {
  strings:
    $key_f0b3 = { a4 db [2] d0 c3 [2] 97 c1 [2] d0 d0 [2] 9e dc [2] 92 d6 [2] 85 dd [2] 9e 93 [2] a3 }

  condition:
    any of them
}