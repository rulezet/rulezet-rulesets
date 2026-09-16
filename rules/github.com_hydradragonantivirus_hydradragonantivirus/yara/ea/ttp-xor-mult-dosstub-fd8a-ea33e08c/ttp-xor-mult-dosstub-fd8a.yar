rule TTP_XOR_MULT_DOSStub_fd8a {
  strings:
    $key_fd8a = { a9 e2 [2] dd fa [2] 9a f8 [2] dd e9 [2] 93 e5 [2] 9f ef [2] 88 e4 [2] 93 aa [2] ae }

  condition:
    any of them
}