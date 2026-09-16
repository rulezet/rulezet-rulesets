rule TTP_XOR_MULT_DOSStub_fd1d {
  strings:
    $key_fd1d = { a9 75 [2] dd 6d [2] 9a 6f [2] dd 7e [2] 93 72 [2] 9f 78 [2] 88 73 [2] 93 3d [2] ae }

  condition:
    any of them
}