rule TTP_XOR_MULT_DOSStub_3cab {
  strings:
    $key_3cab = { 68 c3 [2] 1c db [2] 5b d9 [2] 1c c8 [2] 52 c4 [2] 5e ce [2] 49 c5 [2] 52 8b [2] 6f }

  condition:
    any of them
}