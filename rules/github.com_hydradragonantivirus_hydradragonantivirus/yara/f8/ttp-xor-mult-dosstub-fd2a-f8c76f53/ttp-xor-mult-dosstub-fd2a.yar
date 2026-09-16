rule TTP_XOR_MULT_DOSStub_fd2a {
  strings:
    $key_fd2a = { a9 42 [2] dd 5a [2] 9a 58 [2] dd 49 [2] 93 45 [2] 9f 4f [2] 88 44 [2] 93 0a [2] ae }

  condition:
    any of them
}