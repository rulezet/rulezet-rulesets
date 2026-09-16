rule TTP_XOR_MULT_DOSStub_abab {
  strings:
    $key_abab = { ff c3 [2] 8b db [2] cc d9 [2] 8b c8 [2] c5 c4 [2] c9 ce [2] de c5 [2] c5 8b [2] f8 }

  condition:
    any of them
}