rule TTP_XOR_MULT_DOSStub_fd7d {
  strings:
    $key_fd7d = { a9 15 [2] dd 0d [2] 9a 0f [2] dd 1e [2] 93 12 [2] 9f 18 [2] 88 13 [2] 93 5d [2] ae }

  condition:
    any of them
}