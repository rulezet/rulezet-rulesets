rule TTP_XOR_MULT_DOSStub_2ebe {
  strings:
    $key_2ebe = { 7a d6 [2] 0e ce [2] 49 cc [2] 0e dd [2] 40 d1 [2] 4c db [2] 5b d0 [2] 40 9e [2] 7d }

  condition:
    any of them
}