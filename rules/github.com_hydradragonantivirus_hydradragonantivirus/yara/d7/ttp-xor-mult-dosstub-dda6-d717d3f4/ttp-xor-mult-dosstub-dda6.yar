rule TTP_XOR_MULT_DOSStub_dda6 {
  strings:
    $key_dda6 = { 89 ce [2] fd d6 [2] ba d4 [2] fd c5 [2] b3 c9 [2] bf c3 [2] a8 c8 [2] b3 86 [2] 8e }

  condition:
    any of them
}