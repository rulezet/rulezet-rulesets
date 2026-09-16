rule TTP_XOR_MULT_DOSStub_fd4e {
  strings:
    $key_fd4e = { a9 26 [2] dd 3e [2] 9a 3c [2] dd 2d [2] 93 21 [2] 9f 2b [2] 88 20 [2] 93 6e [2] ae }

  condition:
    any of them
}