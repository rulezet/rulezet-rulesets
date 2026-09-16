rule TTP_XOR_MULT_DOSStub_492a {
  strings:
    $key_492a = { 1d 42 [2] 69 5a [2] 2e 58 [2] 69 49 [2] 27 45 [2] 2b 4f [2] 3c 44 [2] 27 0a [2] 1a }

  condition:
    any of them
}