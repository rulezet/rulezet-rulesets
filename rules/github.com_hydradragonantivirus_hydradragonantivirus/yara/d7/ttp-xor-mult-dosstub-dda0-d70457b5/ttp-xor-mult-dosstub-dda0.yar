rule TTP_XOR_MULT_DOSStub_dda0 {
  strings:
    $key_dda0 = { 89 c8 [2] fd d0 [2] ba d2 [2] fd c3 [2] b3 cf [2] bf c5 [2] a8 ce [2] b3 80 [2] 8e }

  condition:
    any of them
}