rule TTP_XOR_MULT_DOSStub_fd1e {
  strings:
    $key_fd1e = { a9 76 [2] dd 6e [2] 9a 6c [2] dd 7d [2] 93 71 [2] 9f 7b [2] 88 70 [2] 93 3e [2] ae }

  condition:
    any of them
}