rule TTP_XOR_MULT_DOSStub_2aab {
  strings:
    $key_2aab = { 7e c3 [2] 0a db [2] 4d d9 [2] 0a c8 [2] 44 c4 [2] 48 ce [2] 5f c5 [2] 44 8b [2] 79 }

  condition:
    any of them
}