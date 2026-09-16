rule TTP_XOR_MULT_DOSStub_f9b4 {
  strings:
    $key_f9b4 = { ad dc [2] d9 c4 [2] 9e c6 [2] d9 d7 [2] 97 db [2] 9b d1 [2] 8c da [2] 97 94 [2] aa }

  condition:
    any of them
}