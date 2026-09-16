rule TTP_XOR_MULT_DOSStub_1ebe {
  strings:
    $key_1ebe = { 4a d6 [2] 3e ce [2] 79 cc [2] 3e dd [2] 70 d1 [2] 7c db [2] 6b d0 [2] 70 9e [2] 4d }

  condition:
    any of them
}