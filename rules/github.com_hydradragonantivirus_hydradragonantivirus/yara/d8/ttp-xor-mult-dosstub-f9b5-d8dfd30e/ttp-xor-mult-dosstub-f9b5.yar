rule TTP_XOR_MULT_DOSStub_f9b5 {
  strings:
    $key_f9b5 = { ad dd [2] d9 c5 [2] 9e c7 [2] d9 d6 [2] 97 da [2] 9b d0 [2] 8c db [2] 97 95 [2] aa }

  condition:
    any of them
}