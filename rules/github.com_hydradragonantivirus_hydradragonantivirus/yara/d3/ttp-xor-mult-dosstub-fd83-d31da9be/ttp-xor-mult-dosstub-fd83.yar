rule TTP_XOR_MULT_DOSStub_fd83 {
  strings:
    $key_fd83 = { a9 eb [2] dd f3 [2] 9a f1 [2] dd e0 [2] 93 ec [2] 9f e6 [2] 88 ed [2] 93 a3 [2] ae }

  condition:
    any of them
}