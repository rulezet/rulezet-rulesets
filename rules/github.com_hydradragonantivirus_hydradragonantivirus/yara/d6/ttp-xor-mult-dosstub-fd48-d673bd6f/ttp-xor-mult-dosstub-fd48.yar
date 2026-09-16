rule TTP_XOR_MULT_DOSStub_fd48 {
  strings:
    $key_fd48 = { a9 20 [2] dd 38 [2] 9a 3a [2] dd 2b [2] 93 27 [2] 9f 2d [2] 88 26 [2] 93 68 [2] ae }

  condition:
    any of them
}