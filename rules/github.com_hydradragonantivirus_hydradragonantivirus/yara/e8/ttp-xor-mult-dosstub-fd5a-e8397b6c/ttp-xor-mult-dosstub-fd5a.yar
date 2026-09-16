rule TTP_XOR_MULT_DOSStub_fd5a {
  strings:
    $key_fd5a = { a9 32 [2] dd 2a [2] 9a 28 [2] dd 39 [2] 93 35 [2] 9f 3f [2] 88 34 [2] 93 7a [2] ae }

  condition:
    any of them
}