rule TTP_XOR_MULT_DOSStub_2ab4 {
  strings:
    $key_2ab4 = { 7e dc [2] 0a c4 [2] 4d c6 [2] 0a d7 [2] 44 db [2] 48 d1 [2] 5f da [2] 44 94 [2] 79 }

  condition:
    any of them
}