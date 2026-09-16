rule TTP_XOR_MULT_DOSStub_fd84 {
  strings:
    $key_fd84 = { a9 ec [2] dd f4 [2] 9a f6 [2] dd e7 [2] 93 eb [2] 9f e1 [2] 88 ea [2] 93 a4 [2] ae }

  condition:
    any of them
}