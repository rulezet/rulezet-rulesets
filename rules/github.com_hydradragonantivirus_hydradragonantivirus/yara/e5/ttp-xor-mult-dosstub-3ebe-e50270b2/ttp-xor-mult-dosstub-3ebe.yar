rule TTP_XOR_MULT_DOSStub_3ebe {
  strings:
    $key_3ebe = { 6a d6 [2] 1e ce [2] 59 cc [2] 1e dd [2] 50 d1 [2] 5c db [2] 4b d0 [2] 50 9e [2] 6d }

  condition:
    any of them
}