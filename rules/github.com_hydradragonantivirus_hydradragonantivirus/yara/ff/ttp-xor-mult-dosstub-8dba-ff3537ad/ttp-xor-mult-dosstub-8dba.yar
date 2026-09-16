rule TTP_XOR_MULT_DOSStub_8dba {
  strings:
    $key_8dba = { d9 d2 [2] ad ca [2] ea c8 [2] ad d9 [2] e3 d5 [2] ef df [2] f8 d4 [2] e3 9a [2] de }

  condition:
    any of them
}