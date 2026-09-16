rule TTP_XOR_MULT_DOSStub_f9b8 {
  strings:
    $key_f9b8 = { ad d0 [2] d9 c8 [2] 9e ca [2] d9 db [2] 97 d7 [2] 9b dd [2] 8c d6 [2] 97 98 [2] aa }

  condition:
    any of them
}