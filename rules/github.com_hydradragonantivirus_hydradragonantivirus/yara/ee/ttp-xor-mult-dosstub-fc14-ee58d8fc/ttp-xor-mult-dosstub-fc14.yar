rule TTP_XOR_MULT_DOSStub_fc14 {
  strings:
    $key_fc14 = { a8 7c [2] dc 64 [2] 9b 66 [2] dc 77 [2] 92 7b [2] 9e 71 [2] 89 7a [2] 92 34 [2] af }

  condition:
    any of them
}