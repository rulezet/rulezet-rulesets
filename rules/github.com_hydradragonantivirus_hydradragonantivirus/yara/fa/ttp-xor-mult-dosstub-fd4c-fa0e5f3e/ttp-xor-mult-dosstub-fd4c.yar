rule TTP_XOR_MULT_DOSStub_fd4c {
  strings:
    $key_fd4c = { a9 24 [2] dd 3c [2] 9a 3e [2] dd 2f [2] 93 23 [2] 9f 29 [2] 88 22 [2] 93 6c [2] ae }

  condition:
    any of them
}