rule TTP_XOR_MULT_DOSStub_4dbe {
  strings:
    $key_4dbe = { 19 d6 [2] 6d ce [2] 2a cc [2] 6d dd [2] 23 d1 [2] 2f db [2] 38 d0 [2] 23 9e [2] 1e }

  condition:
    any of them
}