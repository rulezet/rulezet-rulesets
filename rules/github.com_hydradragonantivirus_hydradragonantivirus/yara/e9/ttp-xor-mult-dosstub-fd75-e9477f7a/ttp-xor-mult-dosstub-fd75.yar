rule TTP_XOR_MULT_DOSStub_fd75 {
  strings:
    $key_fd75 = { a9 1d [2] dd 05 [2] 9a 07 [2] dd 16 [2] 93 1a [2] 9f 10 [2] 88 1b [2] 93 55 [2] ae }

  condition:
    any of them
}