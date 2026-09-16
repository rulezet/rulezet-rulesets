rule TTP_XOR_MULT_DOSStub_2dbe {
  strings:
    $key_2dbe = { 79 d6 [2] 0d ce [2] 4a cc [2] 0d dd [2] 43 d1 [2] 4f db [2] 58 d0 [2] 43 9e [2] 7e }

  condition:
    any of them
}