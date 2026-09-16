rule TTP_XOR_MULT_DOSStub_eebe {
  strings:
    $key_eebe = { ba d6 [2] ce ce [2] 89 cc [2] ce dd [2] 80 d1 [2] 8c db [2] 9b d0 [2] 80 9e [2] bd }

  condition:
    any of them
}