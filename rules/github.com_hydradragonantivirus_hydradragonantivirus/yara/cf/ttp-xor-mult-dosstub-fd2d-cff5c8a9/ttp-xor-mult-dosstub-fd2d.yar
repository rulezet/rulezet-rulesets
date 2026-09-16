rule TTP_XOR_MULT_DOSStub_fd2d {
  strings:
    $key_fd2d = { a9 45 [2] dd 5d [2] 9a 5f [2] dd 4e [2] 93 42 [2] 9f 48 [2] 88 43 [2] 93 0d [2] ae }

  condition:
    any of them
}