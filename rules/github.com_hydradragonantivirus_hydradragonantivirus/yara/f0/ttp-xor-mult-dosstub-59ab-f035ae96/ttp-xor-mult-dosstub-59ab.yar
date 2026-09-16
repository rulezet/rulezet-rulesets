rule TTP_XOR_MULT_DOSStub_59ab {
  strings:
    $key_59ab = { 0d c3 [2] 79 db [2] 3e d9 [2] 79 c8 [2] 37 c4 [2] 3b ce [2] 2c c5 [2] 37 8b [2] 0a }

  condition:
    any of them
}