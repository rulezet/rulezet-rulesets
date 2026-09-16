rule TTP_XOR_MULT_DOSStub_4931 {
  strings:
    $key_4931 = { 1d 59 [2] 69 41 [2] 2e 43 [2] 69 52 [2] 27 5e [2] 2b 54 [2] 3c 5f [2] 27 11 [2] 1a }

  condition:
    any of them
}