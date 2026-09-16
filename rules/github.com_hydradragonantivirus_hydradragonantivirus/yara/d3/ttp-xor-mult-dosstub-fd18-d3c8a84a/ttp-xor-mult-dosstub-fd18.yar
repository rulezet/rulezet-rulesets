rule TTP_XOR_MULT_DOSStub_fd18 {
  strings:
    $key_fd18 = { a9 70 [2] dd 68 [2] 9a 6a [2] dd 7b [2] 93 77 [2] 9f 7d [2] 88 76 [2] 93 38 [2] ae }

  condition:
    any of them
}